package com.mao.sso.auth.dcr;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import com.mao.sso.support.IntegrationTestSupport;
import com.mao.sso.support.TestDataFactory;

/**
 * DCR 限流防护：同一 IP 超过每分钟注册上限后返回 429 语义的错误。</p>
 *
 * <p>注：本类原先以静态内部类的形式写在 {@code DcrAbuseProtectionTest} 中，
 * Surefire 的文件名匹配规则（{@code *Test.java}）不会包含
 * {@code Outer$Inner.class}，导致用例长期未被真正执行。拆成顶层类后才会进入测试集。</p>
 */
@SpringBootTest(properties = { "sso.dcr.enabled=true", "sso.dcr.max-registrations-per-minute=1" })
@AutoConfigureMockMvc
class DcrRateLimitTest extends IntegrationTestSupport {

	private static final String REDIRECT_URI = "http://localhost:9200/rate-limited-callback";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	@DisplayName("超出每分钟注册上限的请求被拒绝")
	void excessRegistrationIsRejected() throws Exception {
		TestDataFactory.createPublicClient(this.registeredClientRepository, "dcr-ratelimit", REDIRECT_URI, false);

		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body()))
			.andExpect(status().isCreated());

		String response = this.mockMvc
			.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body()))
			.andExpect(status().isBadRequest())
			.andReturn()
			.getResponse()
			.getContentAsString(StandardCharsets.UTF_8);
		assertThat(response).contains("注册过于频繁");
	}

	private static String body() {
		return """
				{"client_name":"dcr-ratelimit","redirect_uris":["%s"],\
				"grant_types":["authorization_code"],"response_types":["code"],\
				"token_endpoint_auth_method":"none","scope":"openid"}
				""".formatted(REDIRECT_URI);
	}

}
