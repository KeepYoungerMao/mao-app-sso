package com.mao.sso.auth.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

import com.mao.sso.auth.token.JwtClaimsCustomizer;
import com.mao.sso.auth.token.PublicClientRefreshTokenGenerator;

/**
 * Spring Authorization Server 基础设施配置。
 *
 * <h3>持久化策略</h3>
 * <ul>
 *   <li>RegisteredClient / Authorization / Consent 全部使用官方 JDBC 实现，
 *       表结构由 Flyway 迁移脚本管理（V2~V4），与官方 schema 完全一致；</li>
 *   <li>Access Token / ID Token 为 JWT（RS256 签名），私钥来自外部配置。</li>
 * </ul>
 *
 * <p>签名密钥（{@code JWKSource}）的加载与校验在 {@link JwkSourceConfig}，
 * 验签器在 {@code api.config.JwtDecoderConfig} —— 三者共用同一个 Bean，此处只负责用。</p>
 */
@Configuration
public class AuthorizationServerConfig {

	private final SsoProperties properties;

	public AuthorizationServerConfig(SsoProperties properties) {
		this.properties = properties;
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
			.issuer(this.properties.getIssuerUrl())
			// 其余端点使用官方默认值：/oauth2/authorize、/oauth2/token、/oauth2/jwks、
			// /.well-known/oauth-authorization-server、/.well-known/openid-configuration、/userinfo
			.build();
	}

	/**
	 * 授权服务器 token 生成链。
	 *
	 * <p>若不定义本 bean，Spring Security 会构建官方默认链，其中
	 * {@code OAuth2RefreshTokenGenerator} 对公共客户端（认证方式 none）不签发 refresh token——
	 * MCP 客户端（全部是公共客户端）将拿不到 refresh token，access token 过期后只能重走浏览器授权。
	 * 定义本 bean 后 {@code OAuth2ConfigurerUtils} 会优先采用容器中的这个生成器。</p>
	 */
	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> authorizationServerTokenGenerator(
			JWKSource<SecurityContext> jwkSource, JwtClaimsCustomizer jwtClaimsCustomizer) {
		JwtGenerator jwtGenerator = new JwtGenerator(new NimbusJwtEncoder(jwkSource));
		// JWT 形态的 access token / id_token：沿用业务 claims 定制（roles、userId 等）
		jwtGenerator.setJwtCustomizer(jwtClaimsCustomizer);
		// 引用（不透明）形态的 access token：当客户端 TokenSettings.accessTokenFormat=REFERENCE 时生效
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		// refresh token：对公共客户端同样签发（MCP 授权规范要求）
		PublicClientRefreshTokenGenerator refreshTokenGenerator = new PublicClientRefreshTokenGenerator();
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

	/**
	 * 授权记录服务：官方 JDBC 实现（表 oauth2_authorization），持久化授权码、Token 及其元数据。
	 *
	 * <p>注入的 {@code RegisteredClientRepository} 由 {@code domain.client.ClientRepositoryConfig} 提供。</p>
	 */
	@Bean
	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService(
				jdbcTemplate, registeredClientRepository);
	}

	/**
	 * 授权同意记录服务：官方 JDBC 实现（表 oauth2_authorization_consent）。
	 */
	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService(
				jdbcTemplate, registeredClientRepository);
	}

}
