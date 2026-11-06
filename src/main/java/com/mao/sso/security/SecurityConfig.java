package com.mao.sso.security;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsProcessor;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.DefaultCorsProcessor;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mao.sso.config.SsoProperties;
import com.mao.sso.oauth.ClientService;
import com.mao.sso.oauth.DcrRateLimiter;
import com.mao.sso.oauth.PreRegisteredClientProvider;
import com.mao.sso.oauth.PublicClientRefreshAuthenticationConverter;
import com.mao.sso.oauth.PublicClientRefreshAuthenticationProvider;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 安全配置：两条 SecurityFilterChain 各司其职。
 *
 * <h3>链 1（@Order(1)）授权服务器链</h3>
 * 仅匹配 Spring Authorization Server 端点（/oauth2/**、/userinfo、/.well-known/**）：
 * <ul>
 *   <li>启用 OIDC 1.0（openid-configuration、userinfo、RP-Initiated Logout）；</li>
 *   <li>自定义授权确认页 /oauth2/consent；</li>
 *   <li>未登录的 HTML 请求重定向到 /login，API 请求返回 401；</li>
 *   <li>CSRF 对端点自动豁免（客户端使用 client_secret_basic / PKCE 认证），
 *       授权确认页通过 state 参数防 CSRF。</li>
 * </ul>
 *
 * <h3>链 2（@Order(2)）普通 Web 链</h3>
 * 登录、退出、首页、个人资料、管理页面：
 * <ul>
 *   <li>表单登录（自定义成功/失败处理器）；</li>
 *   <li>Session Fixation 防护（changeSessionId，保留授权请求状态）；</li>
 *   <li>CSRF 默认启用；CORS 默认拒绝一切跨域请求；</li>
 *   <li>安全响应头（CSP、Frame-Options、Referrer-Policy、HSTS 可配置）。</li>
 * </ul>
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig {

	private static final Logger log = LoggerFactory.getLogger(SecurityConfig.class);

	static final String LOGIN_PAGE = "/login";

	static final String CONSENT_PAGE = "/oauth2/consent";

	static final String SESSION_COOKIE_NAME = "SSO_SESSION";

	/**
	 * 动态客户端注册端点：
	 * <ul>
	 *   <li>{@code /oauth2/register}（RFC 7591）：支持开放注册（{@code setOpenRegistrationAllowed}）；</li>
	 *   <li>{@code /connect/register}（OIDC Registration）：Spring Authorization Server 的实现
	 *       强制校验 initial access token，无法匿名开放，故不启用，避免暴露一个必然失败的端点。</li>
	 * </ul>
	 */
	private static final String[] DCR_ENDPOINTS = { "/oauth2/register" };

	/**
	 * 需要开放跨域访问的端点（RFC 8414 发现 + RFC 7591 注册 + JWKS + UserInfo）。
	 * 浏览器内运行的 MCP / SPA 客户端必须先读取元数据才能发起授权，CORS 默认拒绝会直接断链。
	 */
	private static final String[] CORS_ENDPOINTS = { "/.well-known/oauth-authorization-server",
			"/.well-known/openid-configuration", "/oauth2/jwks", "/oauth2/register", "/userinfo" };

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

	private final SsoProperties properties;

	private final ClientService clientService;

	private final boolean hstsEnabled;

	public SecurityConfig(LoginSuccessHandler loginSuccessHandler, LoginFailureHandler loginFailureHandler,
			SsoProperties properties, ClientService clientService,
			@Value("${sso.hsts-enabled:false}") boolean hstsEnabled) {
		this.loginSuccessHandler = loginSuccessHandler;
		this.loginFailureHandler = loginFailureHandler;
		this.properties = properties;
		this.clientService = clientService;
		this.hstsEnabled = hstsEnabled;
	}

	/**
	 * 授权服务器安全链。
	 */
	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			ObjectProvider<RegisteredClientRepository> registeredClientRepository,
			ObjectProvider<OAuth2AuthorizationService> authorizationService) throws Exception {
		SsoProperties.Dcr dcr = this.properties.getDcr();
		SsoProperties.Metadata metadataProperties = this.properties.getMetadata();
		http.oauth2AuthorizationServer((authorizationServer) -> {
			authorizationServer
				// 启用 OpenID Connect 1.0：/.well-known/openid-configuration、/userinfo
				.oidc(withDefaults())
				// 自定义授权确认页
				.authorizationEndpoint((authorizationEndpoint) -> authorizationEndpoint.consentPage(CONSENT_PAGE))
				// 补齐发现元数据：public client 支持与 scopes_supported（MCP 等客户端依赖）
				.authorizationServerMetadataEndpoint(
						(metadataEndpoint) -> metadataEndpoint.authorizationServerMetadataCustomizer(
								(metadata) -> customizeMetadata(metadata, metadataProperties)));
			if (dcr.isEnabled()) {
				// 必须先配置端点，再取 endpointsMatcher：DCR 端点需要被纳入授权服务器链
				configureDynamicClientRegistration(authorizationServer, registeredClientRepository.getObject(),
						authorizationService.getObject(), this.clientService, dcr);
			}
			// 公共客户端（MCP 等，认证方式 none）的 refresh_token 请求没有 code_verifier，
			// 官方 PublicClientAuthenticationConverter / Provider 都不认（会 401 / invalid_grant）。
			// 必须挂在 clientAuthentication（OAuth2ClientAuthenticationFilter）上，
			// 而不是 tokenEndpoint：客户端认证失败时请求根本到不了 grant 转换阶段。
			// 转换器 + Provider 都排在官方组件之前，只接管「无凭据 + refresh_token」这一种请求。
			authorizationServer.clientAuthentication((clientAuthentication) -> clientAuthentication
				.authenticationConverters(
						(converters) -> converters.add(0, new PublicClientRefreshAuthenticationConverter()))
				.authenticationProviders((providers) -> providers.add(0,
						new PublicClientRefreshAuthenticationProvider(registeredClientRepository.getObject()))));
			http.securityMatcher(authorizationServer.getEndpointsMatcher());
		});
		// 授权确认页提交后，SAS 会 302 到客户端 redirect_uri；当它是自定义协议时，
		// Chromium 浏览器会静默丢弃该跳转（详见 CustomSchemeRedirectFilter 注释），
		// 这里把此类重定向改写为中间页，由用户点击链接完成最后一跳。
		// 锚点用 AuthorizationFilter：SAS 的授权端点过滤器是以 addFilterAfter(..., AuthorizationFilter)
		// 注册的，按端点过滤器类反查不到已注册顺序。
		http.addFilterBefore(new CustomSchemeRedirectFilter(), AuthorizationFilter.class);
		http.authorizeHttpRequests((authorize) -> {
			if (dcr.isEnabled()) {
				if (dcr.isRequireAuthentication()) {
					// 受保护模式：只有已登录管理员可登记客户端
					authorize.requestMatchers(DCR_ENDPOINTS).hasRole("ADMIN");
				}
				else {
					// 开放模式：MCP 等无凭据客户端可自助登记（受 DcrPolicy 白名单与限流约束）
					authorize.requestMatchers(DCR_ENDPOINTS).permitAll();
				}
			}
			authorize.anyRequest().authenticated();
		});
		if (dcr.isEnabled()) {
			// 注册端点为纯 API 调用（无会话、无表单），豁免 CSRF
			http.csrf((csrf) -> csrf.ignoringRequestMatchers(DCR_ENDPOINTS));
		}
		if (metadataProperties.isCorsEnabled()) {
			// 发现端点与注册端点对浏览器内客户端（MCP Web / SPA）开放只读跨域访问
			http.cors((cors) -> cors.configurationSource(discoveryCorsConfigurationSource()));
		}
		http.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
				new LoginUrlAuthenticationEntryPoint(LOGIN_PAGE), htmlRequestMatcher()));
		return http.build();
	}

	/**
	 * 定制 RFC 8414 发现元数据。
	 *
	 * <p>Spring Authorization Server 默认不在 {@code token_endpoint_auth_methods_supported}
	 * 中包含 {@code none}，也不输出 {@code scopes_supported}。MCP 客户端普遍是 public client
	 * （无密钥 + PKCE），且需要通过元数据获知可请求的 scope，两者缺失都会让客户端在
	 * 发现阶段就中止流程。</p>
	 */
	private static void customizeMetadata(
			org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata.Builder metadata,
			SsoProperties.Metadata properties) {
		if (properties.isAllowPublicClients()) {
			metadata.tokenEndpointAuthenticationMethods((methods) -> {
				if (!methods.contains("none")) {
					methods.add("none");
				}
			});
		}
		List<String> scopes = properties.getScopesSupported();
		if (scopes != null && !scopes.isEmpty()) {
			metadata.scopes((declared) -> {
				declared.clear();
				declared.addAll(scopes);
			});
		}
	}

	/**
	 * 发现端点的 CORS 预检（OPTIONS）过滤器，注册在安全过滤链之前。
	 *
	 * <p>它必须位于 FilterChainProxy 之前有两个原因：</p>
	 * <ol>
	 *   <li>OPTIONS 请求不会被授权服务器端点的 securityMatcher 命中，会落到 Web 链，
	 *       而 Web 链的 CORS 策略是「默认拒绝」，预检必然 403；</li>
	 *   <li>Spring Security 7 的 {@link CorsFilter} 把预检委派给 Spring MVC 的处理器映射，
	 *       授权服务器端点由 Filter 实现、没有对应 HandlerMapping，同样会被判为无效请求。</li>
	 * </ol>
	 *
	 * <p>该过滤器只对 {@code sso.metadata.cors-enabled=true} 时登记的若干端点生效，
	 * 其余请求直接放行，不改变「默认拒绝跨域」的整体策略。</p>
	 */
	@Bean
	FilterRegistrationBean<DiscoveryPreFlightFilter> discoveryPreFlightFilter() {
		FilterRegistrationBean<DiscoveryPreFlightFilter> registration = new FilterRegistrationBean<>(
				new DiscoveryPreFlightFilter(discoveryCorsConfigurationSource()));
		registration.setOrder(Ordered.HIGHEST_PRECEDENCE);
		return registration;
	}

	private CorsConfigurationSource discoveryCorsConfigurationSource() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		if (!this.properties.getMetadata().isCorsEnabled()) {
			// 关闭时返回空配置源：getCorsConfiguration 恒为 null，过滤器直接放行
			return source;
		}
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(this.properties.getMetadata().getCorsAllowedOrigins());
		configuration.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
		configuration.setAllowedHeaders(List.of("*"));
		configuration.setExposedHeaders(List.of("WWW-Authenticate", "MCP-Protocol-Version", "Location"));
		configuration.setAllowCredentials(false);
		configuration.setMaxAge(3600L);
		for (String path : CORS_ENDPOINTS) {
			source.registerCorsConfiguration(path, configuration);
		}
		return source;
	}

	/** 仅处理 CORS 预检（OPTIONS）的过滤器：命中配置即响应，否则放行。 */
	static final class DiscoveryPreFlightFilter extends OncePerRequestFilter {

		private final CorsConfigurationSource configurationSource;

		private final CorsProcessor processor = new DefaultCorsProcessor();

		DiscoveryPreFlightFilter(CorsConfigurationSource configurationSource) {
			this.configurationSource = configurationSource;
		}

		@Override
		protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
				FilterChain filterChain) throws ServletException, IOException {
			CorsConfiguration configuration = this.configurationSource.getCorsConfiguration(request);
			if (configuration != null && CorsUtils.isPreFlightRequest(request)) {
				this.processor.processRequest(configuration, request, response);
				return;
			}
			filterChain.doFilter(request, response);
		}

	}

	/**
	 * 启用动态客户端注册（RFC 7591，端点 /oauth2/register）。
	 *
	 * <p>所有客户端必须在管理后台预先录入。DCR 端点收到注册请求后，
	 * 先按 redirect_uri 查表检验是否已预录入，命中则用预录入数据构造标准
	 * OAuth2ClientRegistrationAuthenticationToken 返回。
	 * 全程不 INSERT 新记录。未预录入的 redirect_uri 会返回 400。</p>
	 */
	private void configureDynamicClientRegistration(OAuth2AuthorizationServerConfigurer authorizationServer,
			RegisteredClientRepository repository, OAuth2AuthorizationService authorizationService,
			ClientService clientService, SsoProperties.Dcr dcr) {
		PreRegisteredClientProvider provider = new PreRegisteredClientProvider(clientService,
				new DcrRateLimiter(dcr.getMaxRegistrationsPerMinute()));
		authorizationServer.clientRegistrationEndpoint((endpoint) -> {
			endpoint.authenticationProviders((providers) -> {
				providers.clear();
				providers.add(provider);
			});
		});
		logDcrOpenInfo(dcr);
	}

	private static void logDcrOpenInfo(SsoProperties.Dcr dcr) {
		log.info("================================================================");
		log.info("动态客户端注册（DCR）已启用。所有客户端必须在管理后台预先录入。");
		log.info("DCR 端点收到注册请求后按 redirect_uri 查表返回固定 client_id。");
		log.info("未预录入的 redirect_uri 会被拒绝。限流={}/min/IP", dcr.getMaxRegistrationsPerMinute());
		log.info("================================================================");
	}

	/**
	 * 普通 Web 应用安全链。
	 */
	@Bean
	@Order(2)
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((authorize) -> authorize
			.requestMatchers("/", LOGIN_PAGE, "/logout-success", "/error", "/css/**", "/favicon.ico",
					"/webjars/**")
			.permitAll()
			.requestMatchers("/admin/**").hasRole("ADMIN")
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
		// CSRF 默认启用（Thymeleaf 模板通过 ${_csrf} 渲染隐藏域）
		http.csrf(withDefaults());
		// CORS 默认拒绝：任何跨域请求（Origin 与主机不同）均返回 403
		http.cors((cors) -> cors.configurationSource(corsConfigurationSource()));
		http.headers((headers) -> {
			headers.contentSecurityPolicy((csp) -> csp.policyDirectives(CSP_POLICY));
			headers.frameOptions((frameOptions) -> frameOptions.deny());
			headers.referrerPolicy((referrer) -> referrer
				.policy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN));
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

	private static MediaTypeRequestMatcher htmlRequestMatcher() {
		MediaTypeRequestMatcher requestMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		requestMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		return requestMatcher;
	}

}
