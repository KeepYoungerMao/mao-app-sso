package com.mao.sso.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
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
 * 开放注册的滥用防护：限流与"仅管理员可注册"模式。
 */
class DcrAbuseProtectionTest {

	@SpringBootTest(properties = { "sso.dcr.enabled=true", "sso.dcr.max-registrations-per-minute=1" })
	@AutoConfigureMockMvc
	static class RateLimitTest extends IntegrationTestSupport {

		@Autowired
		private MockMvc mockMvc;

		@Test
		@DisplayName("超出每分钟注册上限的请求被拒绝")
		void excessRegistrationIsRejected() throws Exception {
			this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body("rl-1")))
				.andExpect(status().isCreated());
			String response = this.mockMvc
				.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body("rl-2")))
				.andExpect(status().isBadRequest())
				.andReturn()
				.getResponse()
				.getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
			assertThat(response).contains("注册过于频繁");
		}

	}

	@SpringBootTest(properties = { "sso.dcr.enabled=true", "sso.dcr.require-authentication=true" })
	@AutoConfigureMockMvc
	static class RequireAuthenticationTest extends IntegrationTestSupport {

		@Autowired
		private MockMvc mockMvc;

		@Test
		@DisplayName("要求认证模式下匿名注册被拒绝")
		void anonymousRegistrationIsRejected() throws Exception {
			this.mockMvc
				.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body("anon")))
				.andExpect(status().isUnauthorized());
		}

	}

	private static String body(String clientName) {
		return """
				{"client_name":"%s","redirect_uris":["http://localhost:9000/callback"],\
				"grant_types":["authorization_code"],"response_types":["code"],\
				"token_endpoint_auth_method":"none","scope":"openid"}
				""".formatted(clientName);
	}

}
