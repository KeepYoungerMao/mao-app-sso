package com.mao.sso.auth.token;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

/**
 * 公共客户端 refresh_token 请求的认证转换器。
 *
 * <p>SAS 官方的 {@code PublicClientAuthenticationConverter} 只识别
 * 「authorization_code + code_verifier」请求（{@code matchesPkceTokenRequest}），
 * refresh_token 请求没有 code_verifier，会因无法完成客户端认证而返回 401——
 * 这意味着公共客户端即便拿到 refresh token 也用不了。</p>
 *
 * <p>本转换器补上这个缺口：{@code grant_type=refresh_token} 且未携带任何客户端凭据
 * （无 Authorization 头、无 client_secret 参数）时，按 {@code client_id} 构造
 * 公共客户端认证令牌；其余情况返回 null，交给官方转换器处理。</p>
 */
public final class PublicClientRefreshAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(grantType)) {
			// 非刷新请求：交给官方转换器（公共客户端授权码请求由官方 PKCE 转换器处理）
			return null;
		}
		if (StringUtils.hasText(request.getHeader(HttpHeaders.AUTHORIZATION))
				|| StringUtils.hasText(request.getParameter(OAuth2ParameterNames.CLIENT_SECRET))) {
			// 已携带客户端凭据：保密客户端，交给官方凭据转换器
			return null;
		}
		String[] clientIds = request.getParameterValues(OAuth2ParameterNames.CLIENT_ID);
		if (clientIds == null || clientIds.length != 1 || !StringUtils.hasText(clientIds[0])) {
			// 缺少 client_id：让框架按标准流程返回 invalid_client
			return null;
		}
		Map<String, Object> additionalParameters = new HashMap<>();
		request.getParameterMap().forEach((key, values) -> {
			if (!OAuth2ParameterNames.CLIENT_ID.equals(key)) {
				additionalParameters.put(key, (values.length == 1) ? values[0] : values);
			}
		});
		return new OAuth2ClientAuthenticationToken(clientIds[0], ClientAuthenticationMethod.NONE, null,
				additionalParameters);
	}

}
