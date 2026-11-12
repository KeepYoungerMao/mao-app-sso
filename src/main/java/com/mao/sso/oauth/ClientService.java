package com.mao.sso.oauth;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.mao.sso.common.audit.AuditContext;
import com.mao.sso.common.page.PageQuery;
import com.mao.sso.common.page.PageResult;
import com.mao.sso.config.SsoProperties;
import com.mao.sso.exception.DuplicateResourceException;
import com.mao.sso.exception.InvalidRequestException;
import com.mao.sso.exception.OperationNotAllowedException;
import com.mao.sso.exception.ResourceNotFoundException;

/**
 * 客户端注册管理服务：创建、查询、更新、删除 OAuth 客户端。
 *
 * <p>所有客户端（无论静态/动态）统一通过此 Service 管理，
 * 数据全部写入 {@code oauth2_registered_client} 表（Spring Authorization Server 官方 schema）。</p>
 *
 * <p>读取全部走 {@link PagingRegisteredClientRepository}：列表 / 详情 / 反查都是单条 SQL
 * （行映射委托给官方实现），不做「先查 id 再逐条 findByClientId」的 N+1 回查。</p>
 *
 * <p>审计字段（created_by / updated_by）不在官方 JDBC 实现负责范围内，
 * 由本类在 save 之后补一次 UPDATE 写入；时间字段依赖表默认值 {@code CURRENT_TIMESTAMP(6)}。</p>
 */
@Service
public class ClientService {

	private static final Logger log = LoggerFactory.getLogger(ClientService.class);

	private final PagingRegisteredClientRepository repository;

	private final JdbcTemplate jdbcTemplate;

	private final PasswordEncoder passwordEncoder;

	private final SsoProperties properties;

	public ClientService(PagingRegisteredClientRepository repository, JdbcTemplate jdbcTemplate,
			PasswordEncoder passwordEncoder, SsoProperties properties) {
		this.repository = repository;
		this.jdbcTemplate = jdbcTemplate;
		this.passwordEncoder = passwordEncoder;
		this.properties = properties;
	}

	/**
	 * 创建新客户端。client_id 必须全局唯一。
	 *
	 * <p><b>项目约定：一个客户端只允许配置一个 redirect_uri。</b>参数刻意设计为单值而非集合，
	 * 使违反约定在编译期就不可能发生，而不是等到运行时才校验。</p>
	 *
	 * @return 创建结果；机密客户端会带回一次性明文密钥（仅此一次可见）
	 */
	public CreatedClient createClient(String clientId, String clientName, String clientSecret,
			List<String> authMethods, List<String> grantTypes, String redirectUri,
			List<String> scopes, boolean requireConsent, boolean requireProofKey) {

		if (!StringUtils.hasText(clientId)) {
			throw new InvalidRequestException("client_id 不能为空");
		}
		if (this.repository.findByClientId(clientId) != null) {
			throw new DuplicateResourceException("client_id 已存在: " + clientId);
		}

		Set<ClientAuthenticationMethod> methods = new LinkedHashSet<>();
		for (String method : authMethods) {
			if (StringUtils.hasText(method)) {
				methods.add(new ClientAuthenticationMethod(method.trim()));
			}
		}
		if (methods.isEmpty()) {
			methods.add(ClientAuthenticationMethod.NONE);
		}

		Set<AuthorizationGrantType> grants = new LinkedHashSet<>();
		for (String grant : grantTypes) {
			if (StringUtils.hasText(grant)) {
				grants.add(new AuthorizationGrantType(grant.trim()));
			}
		}
		if (grants.isEmpty()) {
			grants.add(AuthorizationGrantType.AUTHORIZATION_CODE);
		}

		String validatedUri = requireSingleRedirectUri(clientId, redirectUri);
		ensureRedirectUriAvailable(clientId, validatedUri);
		Set<String> scopeSet = new LinkedHashSet<>(scopes);

		boolean confidential = methods.stream()
			.anyMatch((m) -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(m)
					|| ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(m)
					|| ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(m));

		String rawSecret = null;
		String encodedSecret = null;
		if (confidential) {
			rawSecret = StringUtils.hasText(clientSecret) ? clientSecret : generateRandomSecret();
			encodedSecret = this.passwordEncoder.encode(rawSecret);
			log.info("客户端 {} 密钥已哈希存储", clientId);
		}

		SsoProperties.Token defaults = this.properties.getToken();
		RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId(clientId)
			.clientIdIssuedAt(Instant.now())
			.clientName(StringUtils.hasText(clientName) ? clientName : clientId)
			.clientSecret(encodedSecret)
			.clientAuthenticationMethods((m) -> m.addAll(methods))
			.authorizationGrantTypes((g) -> g.addAll(grants))
			.scopes((s) -> s.addAll(scopeSet))
			.redirectUri(validatedUri)
			.clientSettings(ClientSettings.builder()
				.requireAuthorizationConsent(requireConsent)
				.requireProofKey(requireProofKey)
				.build())
			.tokenSettings(TokenSettings.builder()
				.accessTokenTimeToLive(defaults.getAccessTokenTtl())
				.refreshTokenTimeToLive(defaults.getRefreshTokenTtl())
				.authorizationCodeTimeToLive(defaults.getAuthorizationCodeTtl())
				.reuseRefreshTokens(defaults.isReuseRefreshTokens())
				.idTokenSignatureAlgorithm(org.springframework.security.oauth2.jose.jws.SignatureAlgorithm.RS256)
				.build())
			.build();

		this.repository.save(client);
		touchAudit(clientId, AuditContext.currentUser(), true);
		log.info("已创建 OAuth 客户端: clientId={} name={} authMethods={} grantTypes={} redirectUri={}",
				clientId, clientName, methods, grants, validatedUri);
		return new CreatedClient(clientId, rawSecret);
	}

	/**
	 * 更新客户端可变属性（名称、redirect_uri、scopes、授权确认与 PKCE 开关）。
	 * client_id / client_secret / grant_types / 认证方式不在本方法内变更。
	 *
	 * <p>{@code redirectUri} 传 {@code null} 或空白表示「保持不变」；传入新值则**整条替换**
	 * （由于约定每个客户端只有一条，替换而非追加，避免越改越多）。</p>
	 */
	public void updateClient(String clientId, String clientName, String redirectUri, List<String> scopes,
			Boolean requireConsent, Boolean requireProofKey) {

		RegisteredClient existing = this.repository.findByClientId(clientId);
		if (existing == null) {
			throw new ResourceNotFoundException("客户端不存在: " + clientId);
		}

		ClientSettings currentSettings = existing.getClientSettings();
		boolean consent = (requireConsent != null) ? requireConsent
				: currentSettings.isRequireAuthorizationConsent();
		boolean proofKey = (requireProofKey != null) ? requireProofKey : currentSettings.isRequireProofKey();

		RegisteredClient.Builder builder = RegisteredClient.from(existing);
		if (StringUtils.hasText(clientName)) {
			builder.clientName(clientName);
		}
		if (StringUtils.hasText(redirectUri)) {
			String validatedUri = requireSingleRedirectUri(clientId, redirectUri);
			ensureRedirectUriAvailable(clientId, validatedUri);
			// 必须 clear 后 add：Builder.redirectUri(String) 是**追加**语义，
			// 直接调用会让客户端从一条变两条，正好违反本项目的约定。
			builder.redirectUris((uris) -> {
				uris.clear();
				uris.add(validatedUri);
			});
		}
		if (scopes != null && !scopes.isEmpty()) {
			Set<String> scopeSet = new LinkedHashSet<>(scopes);
			builder.scopes((current) -> {
				current.clear();
				current.addAll(scopeSet);
			});
		}
		builder.clientSettings(ClientSettings.withSettings(currentSettings.getSettings())
			.requireAuthorizationConsent(consent)
			.requireProofKey(proofKey)
			.build());

		this.repository.save(builder.build());
		touchAudit(clientId, AuditContext.currentUser(), false);
		log.info("已更新 OAuth 客户端: clientId={}", clientId);
	}

	/**
	 * 重新生成客户端密钥（仅适用于 confidential 客户端）。
	 * @return 新密钥明文（仅此一次可见，请立即复制）
	 */
	public String regenerateSecret(String clientId) {
		RegisteredClient client = this.repository.findByClientId(clientId);
		if (client == null) {
			throw new ResourceNotFoundException("客户端不存在: " + clientId);
		}
		String rawSecret = generateRandomSecret();
		RegisteredClient updated = RegisteredClient.from(client)
			.clientSecret(this.passwordEncoder.encode(rawSecret))
			.build();
		this.repository.save(updated);
		touchAudit(clientId, AuditContext.currentUser(), false);
		log.info("客户端 {} 密钥已重新生成", clientId);
		return rawSecret;
	}

	/**
	 * 删除客户端（直接从 oauth2_registered_client 表 DELETE）。
	 *
	 * <p>管理控制台自身客户端不允许删除，否则将失去唯一的运维入口。</p>
	 */
	public void deleteClient(String clientId) {
		RegisteredClient client = this.repository.findByClientId(clientId);
		if (client == null) {
			throw new ResourceNotFoundException("客户端不存在: " + clientId);
		}
		if (clientId.equals(this.properties.getAdminApi().getClientId())) {
			throw new OperationNotAllowedException("不能删除管理控制台自身客户端: " + clientId);
		}
		this.jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE client_id = ?", clientId);
		log.info("已删除 OAuth 客户端: clientId={}", clientId);
	}

	/**
	 * 客户端分页查询（按 client_id_issued_at 倒序，同秒并列时按主键兜底）。
	 *
	 * <p>单条 SQL 取回整页（含审计字段）：计数与取数据各一次查询，
	 * 与页大小无关。返回 {@link ClientDetail} 而非 {@link RegisteredClient}，
	 * 是因为列表页要展示 created_by / updated_at，逐条回查会退化成 3N 次查询。</p>
	 */
	public PageResult<ClientDetail> pageClients(PageQuery query, String keyword) {
		long total;
		if (!query.isRecount() && query.getLastHitCount() != null) {
			total = query.getLastHitCount();
		}
		else {
			total = this.repository.count(keyword);
		}

		List<ClientDetail> records = (query.offset() < total)
				? this.repository.findPage(keyword, query.limit(), query.offset())
					.stream()
					.map(ClientDetail::from)
					.toList()
				: List.of();
		return new PageResult<>(query.normalizedPageNum(), query.normalizedPageSize(), total, records);
	}

	/** 客户端详情（含审计字段）。 */
	public ClientDetail requireDetail(String clientId) {
		return this.repository.findRowByClientId(clientId)
			.map(ClientDetail::from)
			.orElseThrow(() -> new ResourceNotFoundException("客户端不存在: " + clientId));
	}

	/**
	 * 按 redirect_uri 精确匹配已预录入的客户端。
	 *
	 * <p>先用一条 SQL 只取 {@code client_id} + {@code redirect_uris} 做内存比对
	 * （逗号切分由官方同一工具方法完成），命中后再按 id 取整行——命中时才多一次查询，
	 * 不再是「先把全表逐条加载成对象再比对」。</p>
	 *
	 * <p>若命中的客户端配了多个回调（只可能来自手工 INSERT 的历史数据），打 WARN 提示：
	 * 本项目约定一个客户端只允许一个 redirect_uri，多值时按签发时间倒序取首个会产生歧义。</p>
	 */
	public RegisteredClient findByExactRedirectUri(String redirectUri) {
		return this.repository.findClientIdByRedirectUri(redirectUri)
			.flatMap((clientId) -> Optional.ofNullable(this.repository.findByClientId(clientId)))
			.map(ClientService::warnIfMultipleRedirectUris)
			.orElse(null);
	}

	private static RegisteredClient warnIfMultipleRedirectUris(RegisteredClient client) {
		Set<String> uris = client.getRedirectUris();
		if (uris.size() > 1) {
			log.warn("客户端 {} 配置了 {} 个 redirect_uri，违反「一个客户端只允许一个回调」的约定"
					+ "（疑似手工 INSERT 的历史数据），按注册顺序取首个命中: {}",
					client.getClientId(), uris.size(), uris);
		}
		return client;
	}

	// ---------- 内部工具 ----------

	private void touchAudit(String clientId, String operator, boolean creating) {
		if (creating) {
			// created_at / updated_at 由表默认值填充，这里只补操作人
			this.jdbcTemplate.update(
					"UPDATE oauth2_registered_client SET created_by = ?, updated_by = ? WHERE client_id = ?",
					operator, operator, clientId);
		}
		else {
			this.jdbcTemplate.update(
					"UPDATE oauth2_registered_client SET updated_by = ?, updated_at = CURRENT_TIMESTAMP(6) "
							+ "WHERE client_id = ?",
					operator, clientId);
		}
	}

	/** 生成 40+ 字符随机密钥 */
	private static String generateRandomSecret() {
		byte[] bytes = new byte[32];
		new SecureRandom().nextBytes(bytes);
		return UUID.randomUUID().toString().replace("-", "")
				+ "-" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	/**
	 * 校验回调地址未被其它客户端占用（<b>写入时拒绝</b>）。
	 *
	 * <p>复用 {@link #findByExactRedirectUri} 的匹配规则，确保「写入时的冲突判定」与
	 * 「DCR 运行时的反查判定」完全一致 —— 两者若各自实现，会出现写入时判定不冲突、
	 * 但运行时反查命中另一个客户端的诡异情况。</p>
	 *
	 * <p>自身占用不算冲突（更新时回调地址保持不变是正常操作）。</p>
	 */
	private void ensureRedirectUriAvailable(String clientId, String redirectUri) {
		RegisteredClient owner = findByExactRedirectUri(redirectUri);
		if (owner != null && !owner.getClientId().equals(clientId)) {
			throw new DuplicateResourceException(
					"redirect_uri 已被客户端 " + owner.getClientId() + " 占用: " + redirectUri);
		}
	}

	/**
	 * 校验并归一化回调地址。
	 *
	 * <p><b>项目约定：一个客户端只允许一个 redirect_uri</b>，因此空白值直接拒绝。</p>
	 *
	 * <p>必须显式拒绝含逗号的 URI：{@code oauth2_registered_client.redirect_uris} 是
	 * <b>逗号分隔</b>字符串（SAS 官方 JDBC 实现的存储格式），一个含逗号的地址写入后
	 * 会被反序列化成两个回调，等于从存储层绕过「一个客户端一个回调」的约定。</p>
	 */
	private static String requireSingleRedirectUri(String clientId, String redirectUri) {
		if (!StringUtils.hasText(redirectUri)) {
			throw new InvalidRequestException("客户端 " + clientId + " 必须配置一个 redirect_uri");
		}
		String trimmed = redirectUri.trim();
		if (trimmed.contains(",")) {
			throw new InvalidRequestException(
					"客户端 " + clientId + " 的 redirect_uri 不允许包含逗号（注册表以逗号分隔存储）: " + trimmed);
		}
		if (trimmed.contains("*")) {
			throw new InvalidRequestException(
					"客户端 " + clientId + " 的 redirect_uri 不允许包含通配符: " + trimmed);
		}
		URI parsed;
		try {
			parsed = URI.create(trimmed);
		}
		catch (IllegalArgumentException ex) {
			throw new InvalidRequestException(
					"客户端 " + clientId + " 的 redirect_uri 非法: " + trimmed, ex);
		}
		if (parsed.getScheme() == null) {
			throw new InvalidRequestException(
					"客户端 " + clientId + " 的 redirect_uri 必须是绝对 URI: " + trimmed);
		}
		return trimmed;
	}

	/**
	 * 客户端创建结果。
	 *
	 * @param clientId 客户端标识
	 * @param clientSecret 一次性明文密钥（公共客户端为 null）
	 */
	public record CreatedClient(String clientId, String clientSecret) {
	}

	/** 客户端详情：注册信息 + 审计信息。 */
	public record ClientDetail(RegisteredClient client, String createdBy, Instant createdAt, String updatedBy,
			Instant updatedAt) {

		static ClientDetail from(PagingRegisteredClientRepository.ClientRow row) {
			return new ClientDetail(row.client(), row.createdBy(), row.createdAt(), row.updatedBy(),
					row.updatedAt());
		}

	}

}
