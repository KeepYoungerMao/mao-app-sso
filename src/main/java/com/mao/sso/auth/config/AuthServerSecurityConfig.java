package com.mao.sso.auth.config;

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
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.CorsProcessor;
import org.springframework.web.cors.CorsUtils;
import org.springframework.web.cors.DefaultCorsProcessor;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.OncePerRequestFilter;

import com.mao.sso.auth.dcr.DcrRateLimiter;
import com.mao.sso.auth.dcr.PreRegisteredClientProvider;
import com.mao.sso.auth.filter.CustomSchemeRedirectFilter;
import com.mao.sso.auth.token.PublicClientRefreshAuthenticationConverter;
import com.mao.sso.auth.token.PublicClientRefreshAuthenticationProvider;
import com.mao.sso.domain.mapper.PagingRegisteredClientRepository;

import static org.springframework.security.config.Customizer.withDefaults;

/**
 * 认证服务器安全链（{@code @Order(1)}）：只匹配 OAuth2 / OIDC 协议端点。
 *
 * <p>匹配范围由 {@code authorizationServer.getEndpointsMatcher()} 决定：
 * {@code /oauth2/**}、{@code /userinfo}、{@code /.well-known/**}（启用 DCR 后还包含注册端点）。
 * 门户页面在 {@link PortalSecurityConfig}（{@code @Order(3)}），
 * 管理 API 在 {@code api.config.ApiSecurityConfig}（{@code @Order(2)}）。</p>
 *
 * <h3>为什么这条链的默认方向与门户相反</h3>
 * <p>本链的主体是协议 API（{@code /oauth2/token}、{@code /userinfo}、{@code /oauth2/register}），
 * 无 {@code Accept} 头的程序调用必须走 SAS 默认的 401，只有明确是浏览器导航
 * （{@code Accept} 含 {@code text/html}）时才跳登录页。门户链正好相反：无法判定时按页面处理。
 * 因此两条链不能共用同一个 {@code RequestKindResolver} 分支。</p>
 */
@Configuration
@EnableWebSecurity
public class AuthServerSecurityConfig {

	private static final Logger log = LoggerFactory.getLogger(AuthServerSecurityConfig.class);

	static final String LOGIN_PAGE = "/login";

	static final String CONSENT_PAGE = "/oauth2/consent";

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

	private final SsoProperties properties;

	private final PagingRegisteredClientRepository clientRepository;

	public AuthServerSecurityConfig(SsoProperties properties, PagingRegisteredClientRepository clientRepository) {
		this.properties = properties;
		this.clientRepository = clientRepository;
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
				configureDynamicClientRegistration(authorizationServer, this.clientRepository, dcr);
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
	 *   <li>Spring Security 7 的 {@code CorsFilter} 把预检委派给 Spring MVC 的处理器映射，
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
			PagingRegisteredClientRepository clientRepository, SsoProperties.Dcr dcr) {
		PreRegisteredClientProvider provider = new PreRegisteredClientProvider(clientRepository,
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
	 * 授权服务器链专用：仅当请求明确是浏览器导航（Accept 含 text/html）时才跳登录页。
	 *
	 * <p>刻意与门户链的匹配器分开：两条链的默认方向相反 ——
	 * 授权服务器链的主体是协议 API，无 Accept 头的程序调用必须走 SAS 默认的 401；
	 * 而门户链的主体是页面，无法判定时按页面处理（302 登录）。</p>
	 */
	private static RequestMatcher browserNavigationMatcher() {
		MediaTypeRequestMatcher requestMatcher = new MediaTypeRequestMatcher(MediaType.TEXT_HTML);
		requestMatcher.setIgnoredMediaTypes(Set.of(MediaType.ALL));
		return requestMatcher;
	}

}
