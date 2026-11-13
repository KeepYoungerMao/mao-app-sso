package com.mao.sso.auth.token;

import java.util.Map;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

/**
 * 公共客户端 refresh_token 请求的客户端认证 Provider。
 *
 * <p>SAS 官方的 {@code PublicClientAuthenticationProvider} 通过
 * {@code CodeVerifierAuthenticator.authenticateRequired} 对公共客户端的 token 请求
 * 一律要求 {@code code_verifier}——refresh 请求没有该参数，会被直接拒绝（invalid_grant）。
 * 配合 {@link PublicClientRefreshAuthenticationConverter} 使用：转换器只对
 * 「无凭据 + grant_type=refresh_token」的请求生成公共客户端认证令牌，本 Provider
 * 排在官方 Provider 之前，仅校验客户端存在且允许 none 认证方式。</p>
 *
 * <p>说明：refresh token 本身即是长期凭据，且公共客户端一律强制 PKCE 授权（DCR 策略），
 * refresh 阶段无需再次校验 code_verifier。</p>
 */
public final class PublicClientRefreshAuthenticationProvider implements AuthenticationProvider {

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private final RegisteredClientRepository registeredClientRepository;

	public PublicClientRefreshAuthenticationProvider(RegisteredClientRepository registeredClientRepository) {
		this.registeredClientRepository = registeredClientRepository;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ClientAuthenticationToken clientAuthentication = (OAuth2ClientAuthenticationToken) authentication;
		if (!ClientAuthenticationMethod.NONE.equals(clientAuthentication.getClientAuthenticationMethod())) {
			return null;
		}
		Map<String, Object> parameters = clientAuthentication.getAdditionalParameters();
		if (parameters == null
				|| !AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(parameters.get(OAuth2ParameterNames.GRANT_TYPE))) {
			// 非刷新请求：交给官方 Provider（授权码 + code_verifier 校验）
			return null;
		}
		String clientId = String.valueOf(clientAuthentication.getPrincipal());
		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		if (registeredClient == null) {
			throw invalidClient("client_id");
		}
		if (!registeredClient.getClientAuthenticationMethods()
			.contains(clientAuthentication.getClientAuthenticationMethod())) {
			throw invalidClient("authentication_method");
		}
		return new OAuth2ClientAuthenticationToken(registeredClient,
				clientAuthentication.getClientAuthenticationMethod(), clientAuthentication.getCredentials());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication);
	}

	private static OAuth2AuthenticationException invalidClient(String parameterName) {
		return new OAuth2AuthenticationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_CLIENT, "客户端认证失败: " + parameterName, ERROR_URI),
				"客户端认证失败: " + parameterName);
	}

}
