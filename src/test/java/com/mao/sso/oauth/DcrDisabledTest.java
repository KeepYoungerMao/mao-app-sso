package com.mao.sso.oauth;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import com.mao.sso.support.IntegrationTestSupport;

/**
 * DCR 关闭时的行为：注册端点不对外提供，元数据不宣告注册端点。
 */
@SpringBootTest(properties = "sso.dcr.enabled=false")
@AutoConfigureMockMvc
class DcrDisabledTest extends IntegrationTestSupport {

	@Autowired
	private MockMvc mockMvc;

	@Test
	@DisplayName("关闭 DCR 后注册端点不可访问")
	void registrationEndpointIsUnavailable() throws Exception {
		String body = """
				{"client_name":"disabled","redirect_uris":["http://localhost:9000/callback"],\
				"grant_types":["authorization_code"],"response_types":["code"],\
				"token_endpoint_auth_method":"none","scope":"openid"}
				""";
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().is4xxClientError());
		this.mockMvc.perform(post("/connect/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().is4xxClientError());
	}

	@Test
	@DisplayName("关闭 DCR 后元数据不宣告 registration_endpoint")
	void metadataDoesNotAdvertiseRegistrationEndpoint() throws Exception {
		this.mockMvc.perform(get("/.well-known/oauth-authorization-server"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.registration_endpoint").doesNotExist());
	}

}
