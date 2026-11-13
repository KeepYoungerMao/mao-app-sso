package com.mao.sso.auth.config;

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
import org.springframework.util.StringUtils;

/**
 * JWT 签名密钥（JWK）的加载与校验。
 *
 * <h3>来源优先级</h3>
 * <ol>
 *   <li>{@code sso.jwk.location} 指向 JWK Set JSON 文件（推荐，支持密钥轮换）；</li>
 *   <li>{@code sso.jwk.location} 指向 Java KeyStore（.jks/.p12/.pfx），配合 {@code sso.jwk.password}；</li>
 *   <li>两者均未配置：仅 {@code allow-ephemeral=true}（开发环境）生成临时密钥并打印 WARN，
 *       重启后历史 Token 失效；生产环境直接启动失败，强制使用持久化密钥。</li>
 * </ol>
 *
 * <p><b>注意</b>：{@code sso.jwk.location} 一旦有值就一定去加载，文件缺失<b>不会</b>回退临时密钥，
 * 而是直接抛 {@code IllegalStateException: JWK 资源不存在} —— {@code allow-ephemeral} 只在
 * location 为空时生效。这是换机器 / 进容器最容易踩的一条。</p>
 *
 * <p>产出的 {@code JWKSource} Bean 有两个消费方：认证服务器签发 Token（本包的
 * {@code AuthorizationServerConfig#authorizationServerTokenGenerator}）与资源服务器验签
 * （{@code api.config.JwtDecoderConfig}）。因此它是两个入口之间的共享契约。</p>
 */
@Configuration(proxyBeanMethods = false)
public class JwkSourceConfig {

	private static final Logger log = LoggerFactory.getLogger(JwkSourceConfig.class);

	private final SsoProperties properties;

	private final ResourceLoader resourceLoader;

	public JwkSourceConfig(SsoProperties properties, ResourceLoader resourceLoader) {
		this.properties = properties;
		this.resourceLoader = resourceLoader;
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

}
