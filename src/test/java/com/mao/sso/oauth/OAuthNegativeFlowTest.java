package com.mao.sso.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Base64;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.mao.sso.support.IntegrationTestSupport;
import com.mao.sso.support.IntegrationTestSupport.PkcePair;
import com.mao.sso.support.TestDataFactory;
import com.mao.sso.user.UserService;

/**
 * OAuth 2.1 负面流程测试：PKCE 强制、严格 redirect_uri / scope / client_id 校验、
 * 禁用 Implicit 等不安全模式。
 */
@SpringBootTest
@AutoConfigureMockMvc
class OAuthNegativeFlowTest extends IntegrationTestSupport {

	private static final String REDIRECT_URI = "http://localhost/callback";

	private static final String EVIL_REDIRECT_URI = "https://evil.example.com/steal";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	@DisplayName("缺少 PKCE code_challenge 时授权请求失败（客户端强制 PKCE）")
	void missingPkceRejected() throws Exception {
		String clientId = "nopkce-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createConfidentialClient(this.registeredClientRepository, this.passwordEncoder, clientId,
				REDIRECT_URI, false, "openid");

		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", "st-1").with(syncQueryString()).accept(MediaType.TEXT_HTML))
			.andExpect(status().is3xxRedirection())
			.andExpect(result -> {
				String location = result.getResponse().getRedirectedUrl();
				assertThat(location).startsWith(REDIRECT_URI);
				assertThat(queryParameter(location, "error")).isEqualTo("invalid_request");
			});
	}

	@Test
	@DisplayName("code_challenge_method=plain 被拒绝（仅支持 S256）")
	void plainCodeChallengeMethodRejected() throws Exception {
		String clientId = "plain-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createConfidentialClient(this.registeredClientRepository, this.passwordEncoder, clientId,
				REDIRECT_URI, false, "openid");

		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", "st-1")
			.param("code_challenge", "anything")
			.param("code_challenge_method", "plain").with(syncQueryString()).accept(MediaType.TEXT_HTML))
			.andExpect(status().is3xxRedirection())
			.andExpect(result -> {
				String location = result.getResponse().getRedirectedUrl();
				assertThat(location).startsWith(REDIRECT_URI);
				assertThat(queryParameter(location, "error")).isEqualTo("invalid_request");
			});
	}

	@Test
	@DisplayName("未注册的 redirect_uri 被拒绝且不发生重定向（防开放重定向）")
	void unregisteredRedirectUriRejected() throws Exception {
		String clientId = "baduri-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createConfidentialClient(this.registeredClientRepository, this.passwordEncoder, clientId,
				REDIRECT_URI, false, "openid");

		MvcResult result = this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", EVIL_REDIRECT_URI)
			.param("state", "st-1").with(syncQueryString()).accept(MediaType.TEXT_HTML))
			.andExpect(status().isBadRequest())
			.andReturn();
		String body = result.getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
		// 框架对 redirect_uri 校验失败不执行重定向（防止把错误导向未注册地址）
		assertThat(result.getResponse().getRedirectedUrl()).isNull();
		assertThat(body).doesNotContain("evil.example.com");
	}

	@Test
	@DisplayName("未注册的 scope 被拒绝")
	void unregisteredScopeRejected() throws Exception {
		String clientId = "badscope-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createConfidentialClient(this.registeredClientRepository, this.passwordEncoder, clientId,
				REDIRECT_URI, false, "openid", "profile");

		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid admin-root")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", "st-1")
			.param("code_challenge", "challenge")
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML))
			.andExpect(status().is3xxRedirection())
			.andExpect(result -> {
				String location = result.getResponse().getRedirectedUrl();
				assertThat(location).startsWith(REDIRECT_URI);
				assertThat(queryParameter(location, "error")).isEqualTo("invalid_scope");
			});
	}

	@Test
	@DisplayName("未知 client_id 被拒绝")
	void unknownClientRejected() throws Exception {
		MvcResult result = this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", "not-exist-client")
			.param("scope", "openid")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", "st-1").with(syncQueryString()).accept(MediaType.TEXT_HTML))
			.andExpect(status().isBadRequest())
			.andReturn();
		assertThat(result.getResponse().getRedirectedUrl()).isNull();
	}

	@Test
	@DisplayName("Implicit Grant（response_type=token）不被支持")
	void implicitGrantRejected() throws Exception {
		String clientId = "implicit-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createConfidentialClient(this.registeredClientRepository, this.passwordEncoder, clientId,
				REDIRECT_URI, false, "openid");

		// 框架对不支持的 response_type 返回 400 且不重定向（无法安全校验重定向目标时不跳转）
		MvcResult result = this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "token")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", "st-1").with(syncQueryString()).accept(MediaType.TEXT_HTML))
			.andExpect(status().isBadRequest())
			.andReturn();
		assertThat(result.getResponse().getRedirectedUrl()).isNull();
		assertThat(result.getResponse().getErrorMessage()).contains("unsupported_response_type");
	}

	@Test
	@DisplayName("Password Grant 不被支持")
	void passwordGrantRejected() throws Exception {
		String clientId = "pwd-" + UUID.randomUUID().toString().substring(0, 8);
		String clientSecret = TestDataFactory.createConfidentialClient(this.registeredClientRepository,
				this.passwordEncoder, clientId, REDIRECT_URI, false, "openid");

		this.mockMvc.perform(post("/oauth2/token")
			.header(HttpHeaders.AUTHORIZATION, "Basic "
					+ Base64.getEncoder().encodeToString((clientId + ":" + clientSecret).getBytes()))
			.param("grant_type", "password")
			.param("username", "someone")
			.param("password", "whatever"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("unsupported_grant_type"));
	}

	@Test
	@DisplayName("客户端密钥错误时 Token 请求返回 401")
	void wrongClientSecretRejected() throws Exception {
		String clientId = "badsecret-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createConfidentialClient(this.registeredClientRepository, this.passwordEncoder, clientId,
				REDIRECT_URI, false, "openid");

		this.mockMvc.perform(post("/oauth2/token")
			.header(HttpHeaders.AUTHORIZATION, "Basic "
					+ Base64.getEncoder().encodeToString((clientId + ":wrong-secret").getBytes()))
			.param("grant_type", "authorization_code")
			.param("code", "whatever")
			.param("redirect_uri", REDIRECT_URI))
			.andExpect(status().isUnauthorized());
	}

	@Test
	@DisplayName("未认证访问 UserInfo 返回 401")
	void userInfoWithoutTokenReturnsUnauthorized() throws Exception {
		this.mockMvc.perform(get("/userinfo"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	@DisplayName("伪造 Access Token 访问 UserInfo 返回 401")
	void userInfoWithInvalidTokenReturnsUnauthorized() throws Exception {
		this.mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer not-a-real-token"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	@DisplayName("授权端点未登录访问重定向到登录页（不返回 Token）")
	void authorizeWithoutLoginRedirectsToLogin() throws Exception {
		String clientId = "anon-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createConfidentialClient(this.registeredClientRepository, this.passwordEncoder, clientId,
				REDIRECT_URI, false, "openid");
		PkcePair pkce = generatePkce();

		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", "st-1")
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML))
			.andExpect(status().is3xxRedirection())
			.andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).isEqualTo("/login"));
	}

	@Test
	@DisplayName("登录后可完成授权（确保匿名测试不影响后续流程）")
	void loggedInUserCanCompleteAuthorization() throws Exception {
		String clientId = "anonok-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createConfidentialClient(this.registeredClientRepository, this.passwordEncoder, clientId,
				REDIRECT_URI, false, "openid");
		String username = "anonok-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		PkcePair pkce = generatePkce();
		String state = "st-" + UUID.randomUUID();

		MockHttpSession session = new MockHttpSession();
		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", state)
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection());

		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.with(csrf())
			.session(session))
			.andExpect(status().is3xxRedirection());

		MvcResult result = this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", state)
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		assertThat(queryParameter(result.getResponse().getRedirectedUrl(), "code")).isNotBlank();
	}

}
