package com.mao.sso.security;

import java.io.IOException;
import java.util.List;
import java.util.Set;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.jspecify.annotations.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsProcessor;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.DefaultCorsProcessor;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mao.sso.config.SsoProperties;
import com.mao.sso.exception.ApiResult;
import com.mao.sso.exception.ErrorCode;
import com.mao.sso.exception.RequestKind;
import com.mao.sso.exception.RequestKindResolver;
import com.mao.sso.oauth.ClientService;
import com.mao.sso.oauth.DcrRateLimiter;
import com.mao.sso.oauth.PreRegisteredClientProvider;
import com.mao.sso.oauth.PublicClientRefreshAuthenticationConverter;
import com.mao.sso.oauth.PublicClientRefreshAuthenticationProvider;

import tools.jackson.databind.ObjectMapper;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 安全配置：三条 SecurityFilterChain 各司其职。
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
 * <h3>链 2（@Order(2)）管理 API 链（OAuth2 Resource Server）</h3>
 * 匹配 {@code /api/v1/admin/**}，用本服务自己签发的 JWT 校验调用方：
 * <ul>
 *   <li>完全无状态（STATELESS）、关闭 CSRF —— 鉴权凭据是 Bearer Token 而非 Cookie；</li>
 *   <li>按<b>角色</b>鉴权：Access Token 的 {@code roles} claim 必须包含
 *       {@code sso.admin-api.required-role}（默认 ADMIN）。scope 只有 openid / profile，
 *       仅用于 OIDC claims 裁剪，不参与接口授权；</li>
 *   <li>CORS 定向放开（仅管理控制台来源），与发现端点的只读跨域策略相互独立；</li>
 *   <li>可由 {@code sso.admin-api.enabled=false} 整体关闭。</li>
 * </ul>
 *
 * <h3>链 3（@Order(3)）普通 Web 链</h3>
 * 登录、退出、首页、个人资料：
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

	private final RequestKindResolver requestKindResolver;

	private final ObjectMapper objectMapper;

	private final boolean hstsEnabled;

	public SecurityConfig(LoginSuccessHandler loginSuccessHandler,
						  LoginFailureHandler loginFailureHandler,
						  SsoProperties properties,
						  ClientService clientService,
						  RequestKindResolver requestKindResolver,
						  ObjectMapper objectMapper,
						  @Value("${sso.hsts-enabled:false}") boolean hstsEnabled) {
		this.loginSuccessHandler = loginSuccessHandler;
		this.loginFailureHandler = loginFailureHandler;
		this.properties = properties;
		this.clientService = clientService;
		this.requestKindResolver = requestKindResolver;
		this.objectMapper = objectMapper;
		this.hstsEnabled = hstsEnabled;
	}

	/**
	 * 授权服务器安全链。
	 */
	@Bean
	@Order(1)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
			ObjectProvider<RegisteredClientRepository> registeredClientRepository) {
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
				configureDynamicClientRegistration(authorizationServer, this.clientService, dcr);
			}
			// 公共客户端（MCP 等，认证方式 none）的 refresh_token 请求没有 code_verifier，
			// 官方 PublicClientAuthenticationConverter / Provider 都不认（会 401 / invalid_grant）。
			// 必须挂在 clientAuthentication（OAuth2ClientAuthenticationFilter）上，
			// 而不是 tokenEndpoint：客户端认证失败时请求根本到不了 grant 转换阶段。
			// 转换器 + Provider 都排在官方组件之前，只接管「无凭据 + refresh_token」这一种请求。
			authorizationServer.clientAuthentication((clientAuthentication) -> clientAuthentication
				.authenticationConverters(
						(converters) -> converters.addFirst(new PublicClientRefreshAuthenticationConverter()))
				.authenticationProviders((providers) -> providers.addFirst(
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
				// DCR 端点面向 MCP / CLI / 桌面端等无会话的程序客户端，必须匿名可调；
				// 唯一的护栏是限流与「redirect_uri 必须已预录入」。需要限制来源时走网络层，
				// 不要加登录态鉴权——那会让 DCR 失去存在意义（详见 SsoProperties.Dcr 注释）。
				authorize.requestMatchers(DCR_ENDPOINTS).permitAll();
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
				new LoginUrlAuthenticationEntryPoint(LOGIN_PAGE), browserNavigationMatcher()));
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
	private static void customizeMetadata(OAuth2AuthorizationServerMetadata.Builder metadata,
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
		protected void doFilterInternal(@NonNull HttpServletRequest request,
										@NonNull HttpServletResponse response,
                                        @NonNull FilterChain filterChain) throws ServletException, IOException {
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
			ClientService clientService, SsoProperties.Dcr dcr) {
		PreRegisteredClientProvider provider = new PreRegisteredClientProvider(clientService,
				new DcrRateLimiter(dcr.getMaxRegistrationsPerMinute()));
		authorizationServer.clientRegistrationEndpoint((endpoint) -> endpoint.authenticationProviders((providers) -> {
            providers.clear();
            providers.add(provider);
        }));
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
	 * 管理 API 安全链：以 OAuth2 Resource Server 形态保护 {@code /api/v1/admin/**}。
	 *
	 * <p>调用方（管理控制台）先用授权码 + PKCE 从本服务拿到 Access Token，
	 * 再以 {@code Authorization: Bearer} 访问。JWT 由本服务自我签发并自我校验
	 * （复用 {@code AuthorizationServerConfig#jwtDecoder}），无需外部依赖。</p>
	 */
	@Bean
	@Order(2)
	@ConditionalOnProperty(prefix = "sso.admin-api", name = "enabled", havingValue = "true",
			matchIfMissing = true)
	SecurityFilterChain adminApiSecurityFilterChain(HttpSecurity http) {
		SsoProperties.AdminApi adminApi = this.properties.getAdminApi();
		http.securityMatcher("/api/v1/admin/**");
		// 授权按角色，不按 scope：scope 只有 openid / profile，仅用于 OIDC claims 裁剪。
		// Access Token 的 roles claim 由 JwtClaimsCustomizer 写入（角色 code 小写），
		// 这里映射成 ROLE_<大写> 供 hasRole 使用。
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest()
			.hasRole(adminApi.getRequiredRole().toUpperCase(java.util.Locale.ROOT)));
		// 凭据是 Bearer Token（不依赖会话 Cookie），因此无状态 + 关闭 CSRF；
		// 401/403 返回标准 WWW-Authenticate 响应头，便于调用方区分认证与授权失败。
		http.oauth2ResourceServer((resourceServer) -> resourceServer
			.jwt((jwt) -> jwt.jwtAuthenticationConverter(adminApiJwtAuthenticationConverter()))
			.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
			.accessDeniedHandler(new BearerTokenAccessDeniedHandler()));
		http.sessionManagement((session) -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.csrf(AbstractHttpConfigurer::disable);
		http.cors((cors) -> cors.configurationSource(adminApiCorsConfigurationSource()));
		return http.build();
	}

	/**
	 * 从 JWT 的 {@code roles} claim 派生 Spring Security 权限。
	 *
	 * <p>默认的 {@code JwtGrantedAuthoritiesConverter} 只读 {@code scope} / {@code scp}，
	 * 会把 scope 映射成 {@code SCOPE_xxx}。本项目 scope 不参与鉴权，因此改为读
	 * {@code roles}，并统一加 {@code ROLE_} 前缀（与 Web 侧
	 * {@code UserDetailsServiceImpl} 的映射保持一致），使 {@code hasRole("ADMIN")} 生效。</p>
	 */
	static Converter<Jwt, AbstractAuthenticationToken> adminApiJwtAuthenticationConverter() {
		JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
		converter.setJwtGrantedAuthoritiesConverter((jwt) -> {
			List<String> roles = jwt.getClaimAsStringList("roles");
			if (roles == null) {
				return List.of();
			}
			return roles.stream()
				.filter(org.springframework.util.StringUtils::hasText)
				.map((role) -> (GrantedAuthority) new SimpleGrantedAuthority(
						"ROLE_" + role.trim().toUpperCase(java.util.Locale.ROOT)))
				.toList();
		});
		return converter;
	}

	/**
	 * 管理 API 的 CORS 策略：只放通 POST/OPTIONS 与 Authorization 头。
	 *
	 * <p>与发现端点的只读跨域策略相互独立：这里携带凭据（Bearer Token），
	 * 因此不允许 {@code allowCredentials=true} + 通配来源的组合，
	 * 生产环境应把 {@code sso.admin-api.cors-allowed-origins} 收敛为管理控制台的实际域名。</p>
	 */
	private CorsConfigurationSource adminApiCorsConfigurationSource() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(this.properties.getAdminApi().getCorsAllowedOrigins());
		configuration.setAllowedMethods(List.of("POST", "OPTIONS"));
		configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
		configuration.setExposedHeaders(List.of("WWW-Authenticate"));
		configuration.setAllowCredentials(false);
		configuration.setMaxAge(3600L);
		source.registerCorsConfiguration("/api/v1/admin/**", configuration);
		return source;
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
	 * 授权服务器链专用：仅当请求明确是浏览器导航（Accept 含 text/html）时才跳登录页。
	 *
	 * <p>刻意不用 {@link #pageRequestMatcher()}：两条链的默认方向相反 ——
	 * 授权服务器链的主体是协议 API（/oauth2/token、/userinfo、/oauth2/register），
	 * 无 Accept 头的程序调用必须走 SAS 默认的 401；而普通 Web 链的主体是页面，
	 * 无法判定时按页面处理（302 登录）。</p>
	 */
	private static RequestMatcher browserNavigationMatcher() {
		MediaTypeRequestMatcher requestMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		requestMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		return requestMatcher;
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
		return (_, response, _) -> writeJsonError(response, HttpStatus.UNAUTHORIZED,
				ErrorCode.UNAUTHORIZED);
	}

	/**
	 * Web 链的授权失败处理：页面请求交 {@code sendError(403)} 渲染错误模板，
	 * API 请求返回 403 JSON 信封。
	 */
	private AccessDeniedHandler webAccessDeniedHandler() {
		return (request, response, _) -> {
			if (this.requestKindResolver.resolve(request) == RequestKind.API) {
				writeJsonError(response, HttpStatus.FORBIDDEN, ErrorCode.ACCESS_DENIED);
			}
			else {
				response.sendError(HttpStatus.FORBIDDEN.value());
			}
		};
	}

	private void writeJsonError(HttpServletResponse response, HttpStatus status, ErrorCode errorCode)
			throws IOException {
		response.setStatus(status.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(java.nio.charset.StandardCharsets.UTF_8.name());
		this.objectMapper.writeValue(response.getWriter(), ApiResult.error(errorCode, errorCode.getDefaultMessage()));
	}

}
