package com.mao.sso.security;

import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.StringUtils;

import com.mao.sso.config.SsoProperties;
import com.mao.sso.oauth.PagingRegisteredClientRepository;
import com.mao.sso.oauth.PublicClientRefreshTokenGenerator;

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
 * <h3>签名密钥（JWK）来源</h3>
 * <ol>
 *   <li>{@code sso.jwk.location} 指向 JWK Set JSON 文件（推荐，支持密钥轮换）；</li>
 *   <li>{@code sso.jwk.location} 指向 Java KeyStore（.jks/.p12/.pfx），配合 {@code sso.jwk.password}；</li>
 *   <li>两者均未配置：仅 dev profile（allow-ephemeral=true）生成临时密钥并打印 WARN，
 *       重启后历史 Token 失效；prod profile 直接启动失败，强制使用持久化密钥。</li>
 * </ol>
 */
@Configuration
public class AuthorizationServerConfig {

	private static final Logger log = LoggerFactory.getLogger(AuthorizationServerConfig.class);

	private final SsoProperties properties;

	private final ResourceLoader resourceLoader;

	public AuthorizationServerConfig(SsoProperties properties, ResourceLoader resourceLoader) {
		this.properties = properties;
		this.resourceLoader = resourceLoader;
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

	@Bean
	public JWKSource<SecurityContext> jwkSource() throws Exception {
		SsoProperties.Jwk jwkProperties = this.properties.getJwk();
		String location = jwkProperties.getLocation();
		if (StringUtils.hasText(location)) {
			return loadJwkSource(location, jwkProperties.getPassword());
		}
		if (jwkProperties.isAllowEphemeral()) {
			log.warn("================================================================");
			log.warn("未配置 sso.jwk.location，已生成临时 RSA 签名密钥（仅限开发环境）。");
			log.warn("该密钥重启后失效：历史 Access/ID Token 将无法验证，refresh token 同步失效。");
			log.warn("生产环境必须配置持久化 JWK Set，参见 README《生产部署注意事项》。");
			log.warn("================================================================");
			return ephemeralJwkSource();
		}
		throw new IllegalStateException(
				"生产环境必须配置持久化签名密钥：请设置 sso.jwk.location（JWK Set JSON 或 KeyStore），"
						+ "或使用环境变量 SSO_JWK_LOCATION");
	}

	private JWKSource<SecurityContext> loadJwkSource(String location, String password) throws Exception {
		Resource resource = this.resourceLoader.getResource(location);
		if (!resource.exists()) {
			throw new IllegalStateException("JWK 资源不存在: " + location);
		}
		String filename = (resource.getFilename() != null) ? resource.getFilename().toLowerCase() : "";
		boolean keystore = filename.endsWith(".jks") || filename.endsWith(".p12") || filename.endsWith(".pfx")
				|| filename.endsWith(".keystore");
		JWKSet jwkSet;
		if (keystore) {
			if (!StringUtils.hasText(password)) {
				throw new IllegalStateException("加载 KeyStore 需要 sso.jwk.password（环境变量 SSO_JWK_PASSWORD）");
			}
			jwkSet = loadFromKeyStore(resource, password);
		}
		else {
			try (InputStream inputStream = resource.getInputStream()) {
				jwkSet = JWKSet.load(inputStream);
			}
		}
		validateSigningKeys(jwkSet, location);
		log.info("已从 {} 加载 JWK Set（包含 {} 个密钥）", location, jwkSet.getKeys().size());
		return new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(jwkSet);
	}

	private static JWKSet loadFromKeyStore(Resource resource, String password) throws Exception {
		String filename = resource.getFilename();
		String type = "JKS";
		if (filename != null && (filename.endsWith(".p12") || filename.endsWith(".pfx"))) {
			type = "PKCS12";
		}
		KeyStore keyStore = KeyStore.getInstance(type);
		try (InputStream inputStream = resource.getInputStream()) {
			keyStore.load(inputStream, password.toCharArray());
		}
		return JWKSet.load(keyStore, (name) -> password.toCharArray());
	}

	private static void validateSigningKeys(JWKSet jwkSet, String location) {
		List<RSAKey> signingKeys = jwkSet.getKeys().stream()
			.filter((key) -> key instanceof RSAKey)
			.map((key) -> (RSAKey) key)
			.filter(RSAKey::isPrivate)
			.toList();
		if (signingKeys.isEmpty()) {
			throw new IllegalStateException("JWK Set 中未找到可用于签名的 RSA 私钥: " + location);
		}
	}

	private static JWKSource<SecurityContext> ephemeralJwkSource() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID(UUID.randomUUID().toString())
			.build();
		return new com.nimbusds.jose.jwk.source.ImmutableJWKSet<>(new JWKSet(rsaKey));
	}

	/**
	 * UserInfo 端点（OAuth2 Resource Server）使用的 JwtDecoder，与签名密钥同源。
	 */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/**
	 * OAuth 客户端仓库：官方 JDBC 实现（表 oauth2_registered_client）的扩展版，
	 * 额外提供「整页单条 SQL」与「按回调地址反查」两类查询，避免 N+1。
	 */
	@Bean
	public PagingRegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		return new PagingRegisteredClientRepository(jdbcTemplate);
	}

	/**
	 * 授权记录服务：官方 JDBC 实现（表 oauth2_authorization），持久化授权码、Token 及其元数据。
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
