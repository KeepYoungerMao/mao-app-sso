package com.mao.sso.auth.dcr;

import java.net.URI;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientRegistrationAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;

import com.mao.sso.domain.mapper.PagingRegisteredClientRepository;

/**
 * DCR 端点预注册 Provider。
 *
 * <p>收到 DCR 请求后按 redirect_uri 精确查表，命中则用预录入的客户端数据构造标准
 * {@link OAuth2ClientRegistrationAuthenticationToken} 返回，由 SAS 官方的
 * {@code OAuth2ClientRegistrationEndpointFilter} 将其序列化为 RFC 7591 标准 JSON 响应。</p>
 *
 * <p>全程不调官方的 {@code OAuth2ClientRegistrationAuthenticationProvider.authenticate()}，
 * 不 INSERT、不 DELETE，只返回预录入记录中的固定 client_id。</p>
 */
public final class PreRegisteredClientProvider implements org.springframework.security.authentication.AuthenticationProvider {

	private static final Logger log = LoggerFactory.getLogger(PreRegisteredClientProvider.class);

	private final PagingRegisteredClientRepository clientRepository;

	private final DcrRateLimiter rateLimiter;

	public PreRegisteredClientProvider(PagingRegisteredClientRepository clientRepository, DcrRateLimiter rateLimiter) {
		this.clientRepository = clientRepository;
		this.rateLimiter = rateLimiter;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// 1. 频率保护
		this.rateLimiter.check();

		// 2. 提取注册请求中的 redirect_uris
		Map<String, Object> requestClaims = extractClaims(authentication);
		List<String> redirectUris = extractRedirectUris(requestClaims);

		// 3. 基础格式校验
		validateBasicFormat(redirectUris);

		// 4. 按 redirect_uri 精确查表（直接访问仓库，不经 ClientService 转接）
		String targetRedirectUri = redirectUris.get(0);
		RegisteredClient preRegistered = this.findByExactRedirectUri(targetRedirectUri);
		if (preRegistered == null) {
			log.warn("DCR 注册被拒：redirect_uri 未预录入: {}", targetRedirectUri);
			throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
					"redirect_uri 未预先录入，请先联系管理员在后台注册客户端: " + targetRedirectUri);
		}

		// 5. 校验请求参数不超出预录入范围
		validateNotExceeding(preRegistered, requestClaims);

		// 6. 用预录入数据构造标准 OAuth2ClientRegistrationAuthenticationToken
		//    不调官方 Provider.authenticate()，不 INSERT 新记录
		log.info("DCR 注册成功（预录入匹配）: clientId={} redirectUri={}",
				preRegistered.getClientId(), targetRedirectUri);
		return buildStandardToken(preRegistered, requestClaims);
	}

	/**
	 * 只接管客户端注册请求。
	 *
	 * <p><b>注意</b>：本 Provider 通过
	 * {@code clientRegistrationEndpoint(...).authenticationProviders(...)} 注册，
	 * 该配置最终落到 {@code HttpSecurity} 全局的 {@link org.springframework.security.authentication.AuthenticationManager}
	 * 上，也就是授权端点、Token 端点、客户端认证过滤器共用同一个 ProviderManager。
	 * 因此这里<b>必须</b>精确断言类型：若返回 {@code true}，任何一次客户端认证失败
	 * 都会被本类的 {@link DcrRejectedException} 覆盖成 {@code invalid_request}，
	 * 真实错误码（{@code invalid_grant} / {@code invalid_client}）随之丢失。</p>
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientRegistrationAuthenticationToken.class.isAssignableFrom(authentication);
	}

	// ---------- 查表 ----------

	/**
	 * 按 redirect_uri 精确匹配已预录入的客户端。
	 *
	 * <p>先用一条 SQL 只取 {@code client_id} + {@code redirect_uris} 做内存比对
	 * （逗号切分由官方同一工具方法完成），命中后再按 id 取整行——命中时才多一次查询。
	 * 与 {@code ClientService} 写入时的回调占用判定走同一个
	 * {@link PagingRegisteredClientRepository#findClientIdByRedirectUri} 匹配查询，
	 * 两边判定规则始终一致。</p>
	 *
	 * <p>若命中的客户端配了多个回调（只可能来自手工 INSERT 的历史数据），打 WARN 提示：
	 * 本项目约定一个客户端只允许一个 redirect_uri，多值时取首个命中会产生歧义。</p>
	 */
	private RegisteredClient findByExactRedirectUri(String redirectUri) {
		return this.clientRepository.findClientIdByRedirectUri(redirectUri)
			.flatMap(clientId -> Optional.ofNullable(this.clientRepository.findByClientId(clientId)))
			.map(PreRegisteredClientProvider::warnIfMultipleRedirectUris)
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

	// ---------- 校验 ----------

	private void validateBasicFormat(List<String> redirectUris) {
		if (redirectUris.isEmpty()) {
			throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
					"客户端注册必须提供至少一个 redirect_uris");
		}
		for (String redirectUri : redirectUris) {
			if (redirectUri.contains("*")) {
				throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
						"redirect_uris 不允许包含通配符: " + redirectUri);
			}
			try {
				URI uri = URI.create(redirectUri);
				if (!StringUtils.hasText(uri.getScheme())) {
					throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
							"redirect_uris 必须是绝对 URI: " + redirectUri);
				}
				if (uri.getFragment() != null) {
					throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
							"redirect_uris 不允许包含片段(#): " + redirectUri);
				}
			}
			catch (IllegalArgumentException ex) {
				throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REDIRECT_URI,
						"redirect_uris 不是合法 URI: " + redirectUri);
			}
		}
	}

	private void validateNotExceeding(RegisteredClient preRegistered, Map<String, Object> claims) {
		List<String> requestedGrants = stringValues(claims.get("grant_types"));
		Set<String> allowedGrants = preRegistered.getAuthorizationGrantTypes().stream()
				.map(g -> g.getValue().toLowerCase())
				.collect(java.util.stream.Collectors.toSet());
		for (String grant : requestedGrants) {
			if (!allowedGrants.contains(grant.toLowerCase())) {
				throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REQUEST,
						"不允许注册的 grant_type: " + grant);
			}
		}

		List<String> requestedScopes = stringValues(claims.get("scope"));
		Set<String> allowedScopes = preRegistered.getScopes().stream()
				.map(String::toLowerCase)
				.collect(java.util.stream.Collectors.toSet());
		for (String scope : requestedScopes) {
			if (!StringUtils.hasText(scope)) {
				continue;
			}
			if (!allowedScopes.contains(scope.toLowerCase())) {
				throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_SCOPE,
						"不允许注册的 scope: " + scope + "（允许范围: " + preRegistered.getScopes() + "）");
			}
		}

		for (String responseType : stringValues(claims.get("response_types"))) {
			if (!"code".equals(responseType)) {
				throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REQUEST,
						"不允许注册的 response_type: " + responseType + "（仅支持 code）");
			}
		}

		// token_endpoint_auth_method 由预录入配置决定，请求只能声明与之相符的值，
		// 否则响应会「宣称一种认证方式、实际按另一种校验」，对客户端是误导。
		Set<String> allowedMethods = preRegistered.getClientAuthenticationMethods()
			.stream()
			.map(m -> m.getValue().toLowerCase())
			.collect(java.util.stream.Collectors.toSet());
		for (String method : stringValues(claims.get("token_endpoint_auth_method"))) {
			if (!allowedMethods.contains(method.toLowerCase())) {
				throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REQUEST,
						"不允许注册的 token_endpoint_auth_method: " + method + "（预录入配置: " + allowedMethods + "）");
			}
		}
	}

	// ---------- Token 构建 ----------

	/**
	 * 用预录入的 RegisteredClient 数据 + 请求中的 redirect_uris 构造标准
	 * {@link OAuth2ClientRegistrationAuthenticationToken}。
	 *
	 * <p>SAS 官方的 {@code OAuth2ClientRegistrationEndpointFilter.sendClientRegistrationResponse()}
	 * 会从返回值中提取 {@code getClientRegistration().getClaims()}，经
	 * {@code OAuth2ClientRegistrationHttpMessageConverter} 序列化为 RFC 7591 JSON 响应。
	 * 这里 ensure 所有 claims 与 SAS 官方返回格式一致。</p>
	 */
	private Authentication buildStandardToken(RegisteredClient preRegistered, Map<String, Object> requestClaims) {
		OAuth2ClientRegistration.Builder builder = OAuth2ClientRegistration.builder();

		// 必填：client_id（固定，预录入的）
		// 注意：SAS 的 OAuth2ClientRegistration 内部用 claims map 存储，
		// builder 不提供直接的 clientId 方法，通过 claims() 设置
		Map<String, Object> claims = new LinkedHashMap<>();
		claims.put("client_id", preRegistered.getClientId());
		claims.put("client_id_issued_at", preRegistered.getClientIdIssuedAt());
		claims.put("client_name", preRegistered.getClientName());

		// redirect_uris：必须使用请求中提交的值（RFC 7591 要求回显）
		List<String> redirectUris = extractRedirectUris(requestClaims);
		for (String uri : redirectUris) {
			builder.redirectUri(uri);
		}

		// grant_types
		for (AuthorizationGrantType grant : preRegistered.getAuthorizationGrantTypes()) {
			builder.grantType(grant.getValue());
		}

		// scope：List 类型
		for (String scope : preRegistered.getScopes()) {
			builder.scope(scope);
		}

		// token_endpoint_auth_method
		if (preRegistered.getClientAuthenticationMethods().isEmpty()) {
			builder.tokenEndpointAuthenticationMethod("none");
		}
		else {
			builder.tokenEndpointAuthenticationMethod(
					preRegistered.getClientAuthenticationMethods().iterator().next().getValue());
		}

		OAuth2ClientRegistration registration = builder.build();

		// 把固定 client_id 等写入 builder 之后，需要通过 claims 再设一次
		// 因为 builder.build() 会重新构建 claims
		Map<String, Object> mergedClaims = new LinkedHashMap<>(registration.getClaims());
		mergedClaims.putAll(claims);

		OAuth2ClientRegistration finalRegistration = OAuth2ClientRegistration.withClaims(mergedClaims).build();

		// principal 为 null（匿名注册模式），框架 Filter 只取 getClientRegistration()
		return new OAuth2ClientRegistrationAuthenticationToken(null, finalRegistration);
	}

	// ---------- 工具 ----------

	private List<String> extractRedirectUris(Map<String, Object> claims) {
		return stringValues(claims.get("redirect_uris"));
	}

	@SuppressWarnings("unchecked")
	private static Map<String, Object> extractClaims(Authentication authentication) {
		try {
			var method = authentication.getClass().getMethod("getClientRegistration");
			Object registration = method.invoke(authentication);
			var claimsMethod = registration.getClass().getMethod("getClaims");
			return (Map<String, Object>) claimsMethod.invoke(registration);
		}
		catch (Exception e) {
			throw new DcrRejectedException(OAuth2ErrorCodes.INVALID_REQUEST,
					"不支持的客户端注册请求类型: " + authentication.getClass().getName());
		}
	}

	private static List<String> stringValues(Object value) {
		if (value instanceof java.util.Collection<?> collection) {
			return collection.stream()
				.map(String::valueOf)
				.map(String::trim)
				.filter(StringUtils::hasText)
				.toList();
		}
		if (value instanceof String text && StringUtils.hasText(text)) {
			return List.of(text.trim());
		}
		return List.of();
	}

}