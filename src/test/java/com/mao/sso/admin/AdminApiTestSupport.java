package com.mao.sso.admin;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.jayway.jsonpath.JsonPath;
import com.mao.sso.support.IntegrationTestSupport;
import com.mao.sso.support.TestDataFactory;
import com.mao.sso.user.UserService;

/**
 * 管理 API 测试基类：提供「以指定角色走完整授权码 + PKCE 流程换取 Access Token」的能力。
 *
 * <p>管理链只认 Bearer Token（不认 Cookie 会话），所以任何端到端用例都得先拿 Token。
 * 把这段流程抽到基类，避免每个测试类各抄一份。</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
public abstract class AdminApiTestSupport extends IntegrationTestSupport {

	@Autowired
	protected MockMvc mockMvc;

	@Autowired
	protected UserService userService;

	@Autowired
	protected PasswordEncoder passwordEncoder;

	@Autowired
	protected RegisteredClientRepository registeredClientRepository;

	/**
	 * 走一遍授权码 + PKCE 流程，拿到指定角色用户的 Access Token。
	 *
	 * @param roleCode 角色 code（如 {@code admin} / {@code customer}）
	 */
	protected String accessTokenFor(String roleCode) throws Exception {
		String clientId = "admin-api-" + UUID.randomUUID().toString().substring(0, 8);
		String redirectUri = "http://localhost:9400/" + clientId + "/callback";
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, redirectUri, false);

		String username = "adm-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username, roleCode);
		PkcePair pkce = generatePkce();
		String state = "st-" + UUID.randomUUID();

		MockHttpSession session = new MockHttpSession();
		// 1) 未登录 → 跳登录页
		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", redirectUri)
			.param("state", state)
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection());

		// 2) 登录
		this.mockMvc
			.perform(post("/login").param("username", username).param("password", password).with(csrf())
				.session(session))
			.andExpect(status().is3xxRedirection());

		// 3) 再访问授权端点（客户端 requireAuthorizationConsent=false）→ 直接回调带 code
		MvcResult authorized = this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", redirectUri)
			.param("state", state)
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String code = queryParameter(authorized.getResponse().getRedirectedUrl(), "code");
		assertThat(code).isNotBlank();

		// 4) public client 换 token：client_id + code_verifier，无客户端密钥
		String body = this.mockMvc
			.perform(post("/oauth2/token").contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.param("grant_type", "authorization_code")
				.param("client_id", clientId)
				.param("code", code)
				.param("redirect_uri", redirectUri)
				.param("code_verifier", pkce.codeVerifier()))
			.andExpect(status().isOk())
			.andReturn()
			.getResponse()
			.getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
		return JsonPath.read(body, "$.access_token");
	}

}
