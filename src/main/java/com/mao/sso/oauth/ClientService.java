package com.mao.sso.oauth;

import java.net.URI;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import com.mao.sso.config.SsoProperties;

/**
 * 客户端注册管理服务：创建、查询、删除 OAuth 客户端。
 *
 * <p>所有客户端（无论静态/动态）统一通过此 Service 管理，
 * 数据全部写入 {@code oauth2_registered_client} 表。</p>
 */
@Service
public class ClientService {

	private static final Logger log = LoggerFactory.getLogger(ClientService.class);

	private final RegisteredClientRepository repository;

	private final JdbcTemplate jdbcTemplate;

	private final PasswordEncoder passwordEncoder;

	private final SsoProperties properties;

	public ClientService(RegisteredClientRepository repository, JdbcTemplate jdbcTemplate,
			PasswordEncoder passwordEncoder, SsoProperties properties) {
		this.repository = repository;
		this.jdbcTemplate = jdbcTemplate;
		this.passwordEncoder = passwordEncoder;
		this.properties = properties;
	}

	/**
	 * 创建新客户端。client_id 必须全局唯一。
	 */
	public RegisteredClient createClient(String clientId, String clientName, String clientSecret,
			List<String> authMethods, List<String> grantTypes, List<String> redirectUris,
			List<String> scopes, boolean requireConsent, boolean requireProofKey) {

		if (!StringUtils.hasText(clientId)) {
			throw new IllegalArgumentException("client_id 不能为空");
		}
		if (repository.findByClientId(clientId) != null) {
			throw new IllegalArgumentException("client_id 已存在: " + clientId);
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

		Set<String> validatedUris = validateRedirectUris(clientId, redirectUris);
		Set<String> scopeSet = new LinkedHashSet<>(scopes);

		boolean confidential = methods.stream()
			.anyMatch((m) -> ClientAuthenticationMethod.CLIENT_SECRET_BASIC.equals(m)
					|| ClientAuthenticationMethod.CLIENT_SECRET_POST.equals(m)
					|| ClientAuthenticationMethod.CLIENT_SECRET_JWT.equals(m));

		String encodedSecret = null;
		if (confidential) {
			String rawSecret = StringUtils.hasText(clientSecret) ? clientSecret : generateRandomSecret();
			encodedSecret = passwordEncoder.encode(rawSecret);
			log.info("客户端 {} 密钥已哈希存储", clientId);
		}

		SsoProperties.Token defaults = properties.getToken();
		RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId(clientId)
			.clientIdIssuedAt(Instant.now())
			.clientName(StringUtils.hasText(clientName) ? clientName : clientId)
			.clientSecret(encodedSecret)
			.clientAuthenticationMethods((m) -> m.addAll(methods))
			.authorizationGrantTypes((g) -> g.addAll(grants))
			.scopes((s) -> s.addAll(scopeSet))
			.redirectUris((u) -> u.addAll(validatedUris))
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

		repository.save(client);
		log.info("已创建 OAuth 客户端: clientId={} name={} authMethods={} grantTypes={} redirectUris={}",
				clientId, clientName, methods, grants, validatedUris);
		return client;
	}

	/**
	 * 重新生成客户端密钥（仅适用于 confidential 客户端）。
	 * @return 新密钥明文（仅此一次可见，请立即复制）
	 */
	public String regenerateSecret(String clientId) {
		RegisteredClient client = repository.findByClientId(clientId);
		if (client == null) {
			throw new IllegalArgumentException("客户端不存在: " + clientId);
		}
		String rawSecret = generateRandomSecret();
		RegisteredClient updated = RegisteredClient.from(client)
			.clientSecret(passwordEncoder.encode(rawSecret))
			.build();
		repository.save(updated);
		log.info("客户端 {} 密钥已重新生成", clientId);
		return rawSecret;
	}

	/**
	 * 删除客户端（直接从 oauth2_registered_client 表 DELETE）。
	 */
	public void deleteClient(String clientId) {
		RegisteredClient client = repository.findByClientId(clientId);
		if (client == null) {
			throw new IllegalArgumentException("客户端不存在: " + clientId);
		}
		jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE client_id = ?", clientId);
		log.info("已删除 OAuth 客户端: clientId={}", clientId);
	}

	/**
	 * 列出所有已注册客户端（按 client_id_issued_at 倒序）。
	 */
	public List<RegisteredClient> listClients() {
		List<String> clientIds = jdbcTemplate.query(
				"SELECT client_id FROM oauth2_registered_client ORDER BY client_id_issued_at DESC",
				(rs, rowNum) -> rs.getString("client_id"));
		List<RegisteredClient> result = new ArrayList<>();
		for (String id : clientIds) {
			RegisteredClient client = repository.findByClientId(id);
			if (client != null) {
				result.add(client);
			}
		}
		return result;
	}

	/**
	 * 按 redirect_uri 精确匹配已预录入的客户端。
	 * 遍历全表在应用层做 Set.contains 精确比对。
	 */
	public RegisteredClient findByExactRedirectUri(String redirectUri) {
		for (RegisteredClient client : listClients()) {
			if (client.getRedirectUris().contains(redirectUri)) {
				return client;
			}
		}
		return null;
	}

	/** 生成 40+ 字符随机密钥 */
	private static String generateRandomSecret() {
		byte[] bytes = new byte[32];
		new SecureRandom().nextBytes(bytes);
		return UUID.randomUUID().toString().replace("-", "")
				+ "-" + java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private static Set<String> validateRedirectUris(String clientId, List<String> redirectUris) {
		Set<String> validated = new LinkedHashSet<>();
		for (String uri : redirectUris) {
			if (!StringUtils.hasText(uri)) {
				continue;
			}
			String trimmed = uri.trim();
			if (trimmed.contains("*")) {
				throw new IllegalArgumentException(
						"客户端 " + clientId + " 的 redirect_uri 不允许包含通配符: " + trimmed);
			}
			try {
				URI parsed = URI.create(trimmed);
				if (parsed.getScheme() == null) {
					throw new IllegalArgumentException(
							"客户端 " + clientId + " 的 redirect_uri 必须是绝对 URI: " + trimmed);
				}
			}
			catch (IllegalArgumentException ex) {
				throw new IllegalArgumentException(
						"客户端 " + clientId + " 的 redirect_uri 非法: " + trimmed, ex);
			}
			validated.add(trimmed);
		}
		return validated;
	}

}