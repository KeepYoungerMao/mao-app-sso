package com.mao.sso.oauth;

import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * 动态客户端注册被策略拒绝时抛出，由 DCR 端点转换为 RFC 7591 的 400 错误响应。
 */
public final class DcrRejectedException extends OAuth2AuthenticationException {

	/** RFC 7591 §3.2.2 注册错误响应。 */
	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc7591#section-3.2.2";

	public DcrRejectedException(String errorCode, String description) {
		super(new OAuth2Error(errorCode, description, ERROR_URI));
	}

}
