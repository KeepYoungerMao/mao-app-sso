package com.mao.sso.oauth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import com.mao.sso.support.IntegrationTestSupport;

/**
 * OIDC Discovery / JWKS 端点测试。
 */
@SpringBootTest
@AutoConfigureMockMvc
class OidcDiscoveryTest extends IntegrationTestSupport {

	@Autowired
	private MockMvc mockMvc;

	@Test
	@DisplayName("OIDC Discovery 端点返回完整配置")
	void openidConfiguration() throws Exception {
		this.mockMvc.perform(get("/.well-known/openid-configuration"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.issuer").value("http://localhost:8080"))
			.andExpect(jsonPath("$.authorization_endpoint").value("http://localhost:8080/oauth2/authorize"))
			.andExpect(jsonPath("$.token_endpoint").value("http://localhost:8080/oauth2/token"))
			.andExpect(jsonPath("$.jwks_uri").value("http://localhost:8080/oauth2/jwks"))
			.andExpect(jsonPath("$.userinfo_endpoint").value("http://localhost:8080/userinfo"))
			.andExpect(jsonPath("$.grant_types_supported").isArray())
			.andExpect(jsonPath("$.code_challenge_methods_supported[0]").value("S256"))
			.andExpect(jsonPath("$.response_types_supported").isArray())
			.andExpect(jsonPath("$.subject_types_supported[0]").value("public"))
			.andExpect(jsonPath("$.id_token_signing_alg_values_supported[0]").value("RS256"));
	}

	@Test
	@DisplayName("RFC 8414 Authorization Server Metadata 端点可用")
	void oauthAuthorizationServerMetadata() throws Exception {
		this.mockMvc.perform(get("/.well-known/oauth-authorization-server"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.issuer").value("http://localhost:8080"))
			.andExpect(jsonPath("$.authorization_endpoint").exists())
			.andExpect(jsonPath("$.token_endpoint").exists());
	}

	@Test
	@DisplayName("Discovery 声明仅支持授权码与刷新令牌（无隐式/密码模式）")
	void onlySecureGrantTypesAdvertised() throws Exception {
		this.mockMvc.perform(get("/.well-known/openid-configuration"))
			.andExpect(status().isOk())
			.andExpect(result -> {
				String json = result.getResponse()
					.getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
				org.assertj.core.api.Assertions.assertThat(json).contains("authorization_code");
				org.assertj.core.api.Assertions.assertThat(json).contains("refresh_token");
				org.assertj.core.api.Assertions.assertThat(json).doesNotContain("implicit");
				org.assertj.core.api.Assertions.assertThat(json).doesNotContain("password");
			});
	}

	@Test
	@DisplayName("JWKS 端点返回 RSA 公钥")
	void jwksReturnsRsaPublicKey() throws Exception {
		this.mockMvc.perform(get("/oauth2/jwks"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.keys").isArray())
			.andExpect(jsonPath("$.keys[0].kty").value("RSA"))
			.andExpect(jsonPath("$.keys[0].kid").isString())
			.andExpect(jsonPath("$.keys[0].n").isString())
			.andExpect(jsonPath("$.keys[0].e").isString());
	}

	@Test
	@DisplayName("JWKS 不包含私钥参数")
	void jwksDoesNotLeakPrivateKey() throws Exception {
		this.mockMvc.perform(get("/oauth2/jwks"))
			.andExpect(status().isOk())
			.andExpect(result -> {
				String json = result.getResponse()
					.getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
				org.assertj.core.api.Assertions.assertThat(json).doesNotContain("\"d\"");
				org.assertj.core.api.Assertions.assertThat(json).doesNotContain("\"p\"");
				org.assertj.core.api.Assertions.assertThat(json).doesNotContain("\"q\"");
			});
	}

}
