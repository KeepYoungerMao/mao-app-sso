package com.mao.sso.auth.config;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.mao.sso.support.IntegrationTestSupport;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * 外部 JWK Set 加载测试（生产环境签名密钥路径）：
 * 从文件加载持久化密钥，JWKS 端点公开该密钥，且不使用临时密钥。
 */
@SpringBootTest
@AutoConfigureMockMvc
class ExternalJwkSourceTest extends IntegrationTestSupport {

	private static final String KEY_ID = "external-test-key";

	private static Path jwkFile;

	static {
		try {
			jwkFile = Files.createTempFile("mao-sso-jwk", ".json");
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
				.privateKey((RSAPrivateKey) keyPair.getPrivate())
				.keyID(KEY_ID)
				.build();
			// 注意：Nimbus 的 toString(boolean) 参数为 publicOnly，false 才会输出私钥
			Files.writeString(jwkFile, new JWKSet(rsaKey).toString(false), StandardCharsets.UTF_8);
		}
		catch (Exception ex) {
			throw new IllegalStateException("测试 JWK 文件生成失败", ex);
		}
	}

	@DynamicPropertySource
	static void jwkProperties(DynamicPropertyRegistry registry) {
		registry.add("sso.jwk.location", () -> "file:" + jwkFile.toAbsolutePath());
		// 明确禁用临时密钥：验证配置了外部密钥时不回退
		registry.add("sso.jwk.allow-ephemeral", () -> "false");
	}

	@Autowired
	private MockMvc mockMvc;

	@Test
	@DisplayName("从外部 JWK Set 文件加载签名密钥并公开到 JWKS 端点")
	void loadsExternalJwkSet() throws Exception {
		this.mockMvc.perform(get("/oauth2/jwks"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.keys").isArray())
			.andExpect(jsonPath("$.keys[0].kid").value(KEY_ID))
			.andExpect(jsonPath("$.keys[0].kty").value("RSA"))
			.andExpect(jsonPath("$.keys[0].d").doesNotExist());
	}

}
