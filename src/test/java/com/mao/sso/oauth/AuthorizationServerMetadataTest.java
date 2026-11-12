package com.mao.sso.oauth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import com.mao.sso.support.IntegrationTestSupport;

/**
 * 授权服务器发现元数据（RFC 8414）测试。
 *
 * <p>MCP / 桌面 / 移动端客户端是 public client（无密钥，依赖 PKCE），且依靠元数据决定
 * 请求哪些 scope。Spring Authorization Server 默认不宣告 {@code scopes_supported}，
 * 也不在 {@code token_endpoint_auth_methods_supported} 中包含 {@code none}，
 * 缺失这两项会让严格的客户端在进入动态注册之前就放弃流程。</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthorizationServerMetadataTest extends IntegrationTestSupport {

	private static final String METADATA = "/.well-known/oauth-authorization-server";

	@Autowired
	private MockMvc mockMvc;

	@Test
	@DisplayName("元数据宣告支持 public client（token_endpoint_auth_method=none）")
	void metadataDeclaresPublicClientSupport() throws Exception {
		this.mockMvc.perform(get(METADATA))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.token_endpoint_auth_methods_supported",
					org.hamcrest.Matchers.hasItem("none")));
	}

	@Test
	@DisplayName("元数据宣告 scopes_supported：只有 openid 与 profile")
	void metadataDeclaresSupportedScopes() throws Exception {
		this.mockMvc.perform(get(METADATA))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.scopes_supported", org.hamcrest.Matchers.containsInAnyOrder("openid", "profile")));
	}

	@Test
	@DisplayName("元数据保留框架默认能力：PKCE S256、授权码、注册端点")
	void metadataKeepsFrameworkDefaults() throws Exception {
		this.mockMvc.perform(get(METADATA))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.code_challenge_methods_supported", org.hamcrest.Matchers.hasItem("S256")))
			.andExpect(jsonPath("$.grant_types_supported",
					org.hamcrest.Matchers.hasItem("authorization_code")))
			.andExpect(jsonPath("$.registration_endpoint").exists());
	}

	@Test
	@DisplayName("发现端点与注册端点支持跨域（浏览器内 MCP 客户端需要）")
	void discoveryEndpointsAllowCors() throws Exception {
		this.mockMvc
			.perform(options(METADATA).header("Origin", "http://localhost:5173")
				.header("Access-Control-Request-Method", "POST")
				.header("Access-Control-Request-Headers", "content-type"))
			.andExpect(status().isOk())
			.andExpect(header().string("Access-Control-Allow-Origin", "*"))
			.andExpect(header().string("Access-Control-Allow-Methods",
					org.hamcrest.Matchers.containsString("POST")));
		this.mockMvc
			.perform(options("/oauth2/register").header("Origin", "http://localhost:5173")
				.header("Access-Control-Request-Method", "POST"))
			.andExpect(status().isOk())
			.andExpect(header().string("Access-Control-Allow-Origin", "*"));
	}

	@Test
	@DisplayName("业务端点仍处于默认拒绝跨域策略之下")
	void businessEndpointsStillDenyCors() throws Exception {
		this.mockMvc.perform(options("/login").header("Origin", "http://evil.example")
				.header("Access-Control-Request-Method", "POST")).andExpect(status().isForbidden());
	}

}
