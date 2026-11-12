package com.mao.sso.exception;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

/**
 * 请求形态判定（全局唯一入口，异常处理与 Security 配置共用）。
 *
 * <p>规则（按优先级）：</p>
 * <ol>
 *   <li>路径以 {@code /api/} 开头 → {@link RequestKind#API}；</li>
 *   <li>Accept 明确声明 JSON（含 {@code application/json} 且不含 {@code text/html}）→ API；</li>
 *   <li>其余（含浏览器地址栏导航、{@code Accept: * /*}）→ {@link RequestKind#PAGE}。</li>
 * </ol>
 *
 * <p>为什么 Accept 只是次级信号：curl / fetch 的默认 Accept 是 {@code * /*}，
 * 不能把它当作「调用方要 JSON」的证据；反过来浏览器导航一定带 {@code text/html}。
 * 若 SPA 用 fetch 访问页面路径并希望拿到 JSON 错误，应显式发送
 * {@code Accept: application/json}。</p>
 *
 * <p>OAuth 端点（/oauth2/**、/userinfo、/.well-known/**）由 Spring Authorization Server
 * 的过滤器处理，不经过本组件。</p>
 */
@Component
public class RequestKindResolver {

	/** 判定请求形态。 */
	public RequestKind resolve(HttpServletRequest request) {
		if (request.getRequestURI().startsWith("/api/")) {
			return RequestKind.API;
		}
		String accept = request.getHeader("Accept");
		if (StringUtils.hasText(accept) && accept.contains("application/json")
				&& !accept.contains("text/html")) {
			return RequestKind.API;
		}
		return RequestKind.PAGE;
	}

}
