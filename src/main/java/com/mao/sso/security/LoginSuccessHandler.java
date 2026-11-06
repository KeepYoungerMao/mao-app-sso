package com.mao.sso.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Objects;

/**
 * 登录成功处理器。
 *
 * <ul>
 *   <li>优先跳转到登录前保存的请求（OAuth 2.1 授权流程依赖此行为）；</li>
 *   <li>其次支持 {@code ?redirect=} 参数，但必须是站内地址；</li>
 *   <li>默认跳转首页。</li>
 * </ul>
 *
 * <p>防开放重定向：所有跳转目标必须经过 {@link #isSafeRedirect} 校验——
 * 仅允许站内相对地址，或与当前请求同源（scheme/host/port 一致）的绝对地址；
 * 拒绝跨域绝对地址、协议相对地址（//evil.com）与反斜杠变体（/\evil.com）。</p>
 *
 * <p>注意：Spring Security 7 的 saved request URL 为绝对地址
 * （如 http://localhost:8080/oauth2/authorize?...），因此必须做同源比较而非简单的相对地址判断。</p>
 */
@Component
public class LoginSuccessHandler extends SavedRequestAwareAuthenticationSuccessHandler {

	private static final Logger log = LoggerFactory.getLogger(LoginSuccessHandler.class);

	private final RequestCache requestCache = new HttpSessionRequestCache();

	public LoginSuccessHandler() {
		setDefaultTargetUrl("/");
		setAlwaysUseDefaultTargetUrl(false);
		setRequestCache(this.requestCache);
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws ServletException, IOException {

		String targetUrl = resolveTargetUrl(request, response);
		if (!isSafeRedirect(targetUrl, request)) {
			log.warn("拦截不安全的登录跳转目标: {}", targetUrl);
			targetUrl = "/";
		}
		log.info("登录成功: username={} 跳转目标: {}", authentication.getName(), targetUrl);
		getRedirectStrategy().sendRedirect(request, response, targetUrl);
		clearAuthenticationAttributes(request);
	}

	private String resolveTargetUrl(HttpServletRequest request, HttpServletResponse response) {
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (savedRequest != null && isSafeRedirect(savedRequest.getRedirectUrl(), request)) {
			return savedRequest.getRedirectUrl();
		}
		String redirectParameter = request.getParameter("redirect");
		if (StringUtils.hasText(redirectParameter) && isSafeRedirect(redirectParameter, request)) {
			return redirectParameter;
		}
		return "/";
	}

	/**
	 * 校验跳转目标是否安全：站内相对地址，或与当前请求同源的绝对地址。
	 */
	static boolean isSafeRedirect(String url, HttpServletRequest request) {
		if (!StringUtils.hasText(url)) {
			return false;
		}
		if (url.startsWith("//") || url.startsWith("/\\")) {
			return false;
		}
		org.springframework.web.util.UriComponents uri;
		try {
			uri = UriComponentsBuilder.fromUriString(url).build();
		}
		catch (IllegalArgumentException ex) {
			return false;
		}
		if (uri.getHost() != null) {
			// 绝对地址：必须与当前请求同源（scheme / host / port 一致）
			if (!Objects.equals(uri.getScheme(), request.getScheme())
					|| !Objects.equals(uri.getHost(), request.getServerName())) {
				return false;
			}
			int uriPort = uri.getPort();
			int requestPort = request.getServerPort();
			int defaultPort = "https".equals(uri.getScheme()) ? 443 : 80;
			return (uriPort == -1 ? defaultPort : uriPort) == requestPort;
		}
		// 相对地址：必须以单个 "/" 开头，且路径部分不含 scheme 或反斜杠
		if (!url.startsWith("/")) {
			return false;
		}
		String path = url.split("[?#]")[0];
		return !path.contains(":") && !path.contains("\\") && !url.contains("\\");
	}

	/**
	 * 仅允许站内相对地址（简单场景与测试使用）。
	 */
	static boolean isSafeLocalUrl(String url) {
		if (!StringUtils.hasText(url) || !url.startsWith("/") || url.startsWith("//") || url.startsWith("/\\")) {
			return false;
		}
		String path = url.split("[?#]")[0];
		return !path.contains(":") && !path.contains("\\") && !url.contains("\\");
	}

}
