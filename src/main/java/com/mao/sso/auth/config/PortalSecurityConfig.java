package com.mao.sso.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.mao.sso.auth.login.LoginFailureHandler;
import com.mao.sso.auth.login.LoginSuccessHandler;
import com.mao.sso.domain.error.ErrorCode;
import com.mao.sso.domain.error.JsonErrorWriter;
import com.mao.sso.domain.error.RequestKind;
import com.mao.sso.domain.error.RequestKindResolver;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 门户安全链（{@code @Order(3)}）：表单登录 + 服务端渲染页面。
 *
 * <p>门户（home / login / profile / logout）本质是身份提供方面向人的入口，
 * 与 {@code /oauth2/authorize} 是同一职责的两半，因此和协议端点一起归在 auth 层。</p>
 *
 * <h3>失败分流</h3>
 * <ul>
 *   <li>页面请求：未认证 → 302 {@code /login}；无权限 → {@code sendError(403)} → 渲染
 *       {@code error/4xx} 模板；</li>
 *   <li>非页面请求：未认证 → 401 JSON 信封（code 10401）；无权限 → 403 JSON 信封（code 10403）。</li>
 * </ul>
 * <p>判定规则与异常处理链共用 {@link RequestKindResolver}，避免出现「这里当页面、那里当 API」的分裂。</p>
 */
@Configuration
public class PortalSecurityConfig {

	private static final String LOGIN_PAGE = "/login";

	private static final String SESSION_COOKIE_NAME = "SSO_SESSION";

	/**
	 * CSP 策略：仅允许同源资源；不使用 unsafe-inline（模板不含内联脚本/样式）；
	 * form-action 限定同源，防止表单外发。
	 */
	private static final String CSP_POLICY = String.join("; ",
			"default-src 'self'",
			"script-src 'self'",
			"style-src 'self'",
			"img-src 'self' data:",
			"font-src 'self'",
			"connect-src 'self'",
			"frame-ancestors 'none'",
			"base-uri 'self'",
			"form-action 'self'");

	private final LoginSuccessHandler loginSuccessHandler;

	private final LoginFailureHandler loginFailureHandler;

	private final RequestKindResolver requestKindResolver;

	private final JsonErrorWriter jsonErrorWriter;

	private final boolean hstsEnabled;

	public PortalSecurityConfig(LoginSuccessHandler loginSuccessHandler,
						  LoginFailureHandler loginFailureHandler,
						  RequestKindResolver requestKindResolver,
						  JsonErrorWriter jsonErrorWriter,
						  @Value("${sso.hsts-enabled:false}") boolean hstsEnabled) {
		this.loginSuccessHandler = loginSuccessHandler;
		this.loginFailureHandler = loginFailureHandler;
		this.requestKindResolver = requestKindResolver;
		this.jsonErrorWriter = jsonErrorWriter;
		this.hstsEnabled = hstsEnabled;
	}

	/**
	 * 普通 Web 应用安全链。
	 */
	@Bean
	@Order(3)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) {
		http.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers("/", LOGIN_PAGE, "/logout-success", "/error", "/css/**", "/js/**", "/favicon.ico",
					"/webjars/**")
			.permitAll()
			.requestMatchers("/profile/**").authenticated()
			.anyRequest().authenticated());
		http.formLogin((formLogin) -> formLogin
			.loginPage(LOGIN_PAGE)
			.loginProcessingUrl(LOGIN_PAGE)
			.usernameParameter("username")
			.passwordParameter("password")
			.successHandler(this.loginSuccessHandler)
			.failureHandler(this.loginFailureHandler)
			.permitAll());
		http.logout((logout) -> logout
			.logoutUrl("/logout")
			.logoutSuccessUrl("/logout-success")
			.invalidateHttpSession(true)
			.clearAuthentication(true)
			.deleteCookies(SESSION_COOKIE_NAME)
			.permitAll());
		// Session Fixation 防护：changeSessionId 保留会话属性（授权请求状态存放于会话）
		http.sessionManagement((session) -> session.sessionFixation().changeSessionId());
		// 认证/授权失败按请求形态分流（判定规则与异常处理链共用 RequestKindResolver）：
		//   页面请求：未认证 → 302 /login；无权限 → sendError(403) → /error → error/4xx 模板
		//   API 请求：未认证 → 401 JSON 信封；无权限 → 403 JSON 信封
		http.exceptionHandling((exceptions) -> exceptions
			.defaultAuthenticationEntryPointFor(new LoginUrlAuthenticationEntryPoint(LOGIN_PAGE),
					pageRequestMatcher())
			.defaultAuthenticationEntryPointFor(jsonAuthenticationEntryPoint(),
					new NegatedRequestMatcher(pageRequestMatcher()))
			.accessDeniedHandler(webAccessDeniedHandler()));
		// CSRF 默认启用（Thymeleaf 模板通过 ${_csrf} 渲染隐藏域）
		http.csrf(withDefaults());
		// CORS 默认拒绝：任何跨域请求（Origin 与主机不同）均返回 403
		http.cors((cors) -> cors.configurationSource(corsConfigurationSource()));
		http.headers((headers) -> {
			headers.contentSecurityPolicy((csp) -> csp.policyDirectives(CSP_POLICY));
			headers.frameOptions(HeadersConfigurer.FrameOptionsConfig::deny);
			headers.referrerPolicy((referrer) -> referrer
				.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN));
			if (this.hstsEnabled) {
				headers.httpStrictTransportSecurity((hsts) -> hsts.includeSubDomains(true).maxAgeInSeconds(31536000));
			}
		});
		return http.build();
	}

	/**
	 * CORS 默认拒绝策略：返回空的 CorsConfiguration。
	 *
	 * <p>同源请求（含带 Origin 头的同源 POST）不经过 CORS 校验，不受影响；
	 * 任何跨域请求（含预检）都会被拒绝并返回 403。</p>
	 */
	@Bean
	CorsConfigurationSource corsConfigurationSource() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration denyAll = new CorsConfiguration();
		// 不设置任何 allowedOrigins/allowedMethods，即拒绝全部跨域访问
		source.registerCorsConfiguration("/**", denyAll);
		return source;
	}

	/**
	 * 页面请求匹配器：委托 {@link RequestKindResolver}（全局唯一判定入口），
	 * 与异常处理链的「渲染错误页 vs 返回 JSON 信封」保持同一套规则。
	 */
	private RequestMatcher pageRequestMatcher() {
		return (request) -> this.requestKindResolver.resolve(request) == RequestKind.PAGE;
	}

	/**
	 * 非页面请求未认证时返回 401 JSON 信封（原来是 Spring Security 默认的 403 空响应，
	 * 调用方无法区分「未登录」与「无权限」）。
	 */
	private AuthenticationEntryPoint jsonAuthenticationEntryPoint() {
		return (_, response, _) -> this.jsonErrorWriter.write(response, HttpStatus.UNAUTHORIZED,
				ErrorCode.UNAUTHORIZED);
	}

	/**
	 * Web 链的授权失败处理：页面请求交 {@code sendError(403)} 渲染错误模板，
	 * API 请求返回 403 JSON 信封。
	 */
	private AccessDeniedHandler webAccessDeniedHandler() {
		return (request, response, _) -> {
			if (this.requestKindResolver.resolve(request) == RequestKind.API) {
				this.jsonErrorWriter.write(response, HttpStatus.FORBIDDEN, ErrorCode.ACCESS_DENIED);
			}
			else {
				response.sendError(HttpStatus.FORBIDDEN.value());
			}
		};
	}

}
