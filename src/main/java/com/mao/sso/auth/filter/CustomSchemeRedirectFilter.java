package com.mao.sso.auth.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;

import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 授权端点「自定义协议重定向」中间页。
 *
 * <p><b>背景</b>：授权确认页的「同意授权」是原生表单 POST。SAS 处理成功后 302 到客户端的
 * {@code redirect_uri}，而 MCP 桌面客户端（如 WorkBuddy）注册的是自定义协议
 * （{@code workbuddy://...}）。Chromium 内核浏览器（Edge / Chrome）对
 * 「POST 导航 → 服务器 302 → 自定义协议」会<b>静默丢弃</b>：不弹窗、不跳转、不报错，
 * 用户点击授权后页面毫无反应（授权码其实已签发，只是浏览器拒绝完成最后一跳）。
 * 相比之下，浏览器被外部程序直接打开时的 GET 导航重定向到自定义协议会正常放行——
 * 这就是「重连一次反而能成功」的原因。</p>
 *
 * <p><b>方案</b>：在授权端点过滤器之前包装响应对象。当 SAS 试图把授权响应重定向到
 * 非 http(s) 协议时，不执行重定向，改为渲染一个中间页：页面上给出一个指向该地址的
 * <b>普通链接</b>。点击链接属于浏览器信任的用户激活导航，必然触发系统的
 * 「打开应用」弹窗，流程得以继续。中间页不包含内联脚本/样式，符合本站 CSP 策略。</p>
 *
 * <p><b>范围</b>：仅拦截 POST 请求产生的重定向（即授权确认页提交与拒绝授权）；
 * GET 直达授权端点产生的重定向保持原样——该路径已被验证可用，不做改变。</p>
 */
public final class CustomSchemeRedirectFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
			FilterChain filterChain) throws ServletException, IOException {
		if (!"POST".equalsIgnoreCase(request.getMethod())) {
			// GET 等请求：授权码请求/错误重定向均走原路径，不包装
			filterChain.doFilter(request, response);
			return;
		}
		filterChain.doFilter(request, new InterstitialResponseWrapper(response));
	}

	/**
	 * 拦截 {@code sendRedirect}：目标为自定义协议时改写为中间页，其余照常放行。
	 */
	private static final class InterstitialResponseWrapper extends HttpServletResponseWrapper {

		private InterstitialResponseWrapper(HttpServletResponse response) {
			super(response);
		}

		@Override
		public void sendRedirect(String location) throws IOException {
			if (isCustomScheme(location)) {
				writeInterstitial(location);
				return;
			}
			super.sendRedirect(location);
		}

		private void writeInterstitial(String location) throws IOException {
			HttpServletResponse response = (HttpServletResponse) getResponse();
			if (response.isCommitted()) {
				// 极端情况：响应已提交，无法改写，退回默认行为
				super.sendRedirect(location);
				return;
			}
			response.setStatus(HttpServletResponse.SC_OK);
			response.setContentType("text/html;charset=UTF-8");
			try (PrintWriter writer = response.getWriter()) {
				writer.write(renderInterstitial(location));
			}
		}

	}

	/**
	 * 判断重定向目标是否为自定义（非 http/https）协议，如 {@code workbuddy://}、
	 * {@code com.example.app:/oauth2redirect}。相对地址视为同源跳转，返回 false。
	 */
	static boolean isCustomScheme(String location) {
		if (location == null || location.isEmpty()) {
			return false;
		}
		int colon = location.indexOf(':');
		if (colon <= 0) {
			return false;
		}
		String scheme = location.substring(0, colon).toLowerCase(Locale.ROOT);
		if (scheme.equals("http") || scheme.equals("https")) {
			return false;
		}
		// RFC 3986 scheme 语法：字母开头，后接字母/数字/+/./-
		return scheme.matches("[a-z][a-z0-9+.\\-]*");
	}

	private static String renderInterstitial(String redirectUrl) {
		boolean failed = redirectUrl.contains("error=");
		String title = failed ? "授权未完成" : "授权成功";
		String lead = failed
				? "授权未能完成，客户端将展示具体的错误原因。请点击下方按钮返回客户端："
				: "授权已记录成功。由于浏览器安全策略，页面无法自动跳转到客户端应用，请点击下方按钮继续：";
		return """
				<!DOCTYPE html>
				<html lang="zh-CN">
				<head>
				<meta charset="UTF-8">
				<meta name="viewport" content="width=device-width, initial-scale=1">
				<title>%s - mao-app-sso</title>
				<link rel="stylesheet" href="/css/main.css">
				</head>
				<body>
				<main class="page-container">
				<section class="card" aria-labelledby="redirect-title">
				<h1 id="redirect-title">%s</h1>
				<p>%s</p>
				<p class="button-group">
				<a class="button primary" href="%s" autofocus>打开客户端应用</a>
				</p>
				<p class="muted small">如果点击后没有任何反应，请确认客户端应用正在运行后重试；也可复制以下地址到浏览器地址栏打开：</p>
				<p class="muted small"><code>%s</code></p>
				</section>
				</main>
				</body>
				</html>
				""".formatted(title, title, lead, escapeHtml(redirectUrl), escapeHtml(redirectUrl));
	}

	private static String escapeHtml(String value) {
		return value.replace("&", "&amp;")
			.replace("<", "&lt;")
			.replace(">", "&gt;")
			.replace("\"", "&quot;");
	}

}
