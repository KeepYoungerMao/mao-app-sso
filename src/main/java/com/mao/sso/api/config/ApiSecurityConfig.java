package com.mao.sso.api.config;

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

/**
 * 管理 API 安全链（资源服务器）：以 OAuth2 Resource Server 形态保护 {@code /api/v1/admin/**}。
 *
 * <p>调用方（管理控制台）先用授权码 + PKCE 从本服务拿到 Access Token，
 * 再以 {@code Authorization: Bearer} 访问。JWT 由本服务自我签发并自我校验
 * （验签器由 {@link JwtDecoderConfig} 提供），无需外部依赖。</p>
 *
 * <p>三条安全链的另外两条在 {@code auth.config} 下：
 * {@code AuthServerSecurityConfig}（{@code @Order(1)} 协议端点）与
 * {@code PortalSecurityConfig}（{@code @Order(3)} 门户页面）。</p>
 */
@Configuration(proxyBeanMethods = false)
public class ApiSecurityConfig {

	private final AdminApiProperties adminApiProperties;

	public ApiSecurityConfig(AdminApiProperties adminApiProperties) {
		this.adminApiProperties = adminApiProperties;
	}

	/**
	 * 管理 API 安全链：以 OAuth2 Resource Server 形态保护 {@code /api/v1/admin/**}。
	 *
	 * <p>可由 {@code sso.admin-api.enabled=false} 整体关闭，此时请求会落到门户 Web 链。</p>
	 */
	@Bean
	@Order(2)
	@ConditionalOnProperty(prefix = "sso.admin-api", name = "enabled", havingValue = "true",
			matchIfMissing = true)
	SecurityFilterChain adminApiSecurityFilterChain(HttpSecurity http) {
		http.securityMatcher("/api/v1/admin/**");
		// 授权按角色，不按 scope：scope 只有 openid / profile，仅用于 OIDC claims 裁剪。
		// Access Token 的 roles claim 由 JwtClaimsCustomizer 写入（角色 code 小写），
		// 这里映射成 ROLE_<大写> 供 hasRole 使用。
		http.authorizeHttpRequests((authorize) -> authorize.anyRequest()
			.hasRole(this.adminApiProperties.getRequiredRole().toUpperCase(java.util.Locale.ROOT)));
		// 凭据是 Bearer Token（不依赖会话 Cookie），因此无状态 + 关闭 CSRF；
		// 401/403 返回标准 WWW-Authenticate 响应头，便于调用方区分认证与授权失败。
		// 注意：这两个 handler 刻意不走 JsonErrorWriter —— OAuth 生态（MCP / CLI）依赖 RFC 6750 格式。
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
	 * {@code roles}，并统一加 {@code ROLE_} 前缀（与门户侧
	 * {@code DbUserDetailsService} 的映射保持一致），使 {@code hasRole("ADMIN")} 生效。</p>
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
		configuration.setAllowedOrigins(this.adminApiProperties.getCorsAllowedOrigins());
		configuration.setAllowedMethods(List.of("POST", "OPTIONS"));
		configuration.setAllowedHeaders(List.of("Authorization", "Content-Type", "Accept"));
		configuration.setExposedHeaders(List.of("WWW-Authenticate"));
		configuration.setAllowCredentials(false);
		configuration.setMaxAge(3600L);
		source.registerCorsConfiguration("/api/v1/admin/**", configuration);
		return source;
	}

}
