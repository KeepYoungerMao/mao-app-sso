package com.mao.sso.auth.portal;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.mao.sso.support.IntegrationTestSupport;
import com.mao.sso.support.TestDataFactory;
import com.mao.sso.api.user.UserService;

/**
 * 登录 / 登出 / 访问控制测试：覆盖正常流程与失败流程。
 */
@SpringBootTest
@AutoConfigureMockMvc
class LoginFlowTest extends IntegrationTestSupport {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	private String createTestUser(String suffix, String... roles) {
		String username = "login-" + suffix + "-" + UUID.randomUUID().toString().substring(0, 6);
		return TestDataFactory.createUser(this.userService, this.passwordEncoder, username, roles);
	}

	@Test
	@DisplayName("登录成功后访问受保护页面")
	void loginSuccessAndAccessProtectedPage() throws Exception {
		String username = "login-ok-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);

		MockHttpSession session = new MockHttpSession();
		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.with(csrf())
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/"));

		this.mockMvc.perform(get("/profile").session(session))
			.andExpect(status().isOk())
			.andExpect(view().name("profile"))
			.andExpect(model().attributeExists("user"));
	}

	@Test
	@DisplayName("密码错误时登录失败（通用提示，不区分原因）")
	void loginFailsWithWrongPassword() throws Exception {
		String username = "login-badpwd-" + UUID.randomUUID().toString().substring(0, 6);
		TestDataFactory.createUser(this.userService, this.passwordEncoder, username, UserService.ROLE_CUSTOMER);

		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", "DefinitelyWrong123")
			.with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login?error=true"));
	}

	@Test
	@DisplayName("登录失败后跟到登录页：渲染错误提示，而不是 5xx 错误页")
	void loginFailureRedirectRendersLoginPageWithError() throws Exception {
		this.mockMvc.perform(post("/login")
			.param("username", "no-such-user-" + UUID.randomUUID().toString().substring(0, 6))
			.param("password", "DefinitelyWrong123")
			.with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login?error=true"));

		// 关键：真的跟到 /login 去渲染一次。只断言重定向 URL 会漏掉
		// 参数解析阶段的故障（曾因 boolean 参数 + ?error 空值打成 500）
		this.mockMvc.perform(get("/login").param("error", "true"))
			.andExpect(status().isOk())
			.andExpect(view().name("login"))
			.andExpect(model().attribute("errorMessage", "用户名或密码错误，请重试"))
			.andExpect(content().string(org.hamcrest.Matchers.containsString("用户名或密码错误")));
	}

	@Test
	@DisplayName("登录页容忍无值的标记参数：/login?error 不报错")
	void loginPageToleratesValuelessFlags() throws Exception {
		// 这两个参数只表示「发生过该事件」，值无意义。外部手工拼 URL 时很可能是无值形式
		this.mockMvc.perform(get("/login").param("error", "").param("logout", ""))
			.andExpect(status().isOk())
			.andExpect(view().name("login"));
	}

	@Test
	@DisplayName("用户不存在时登录失败（与密码错误返回相同提示，防枚举）")
	void loginFailsWithUnknownUser() throws Exception {
		this.mockMvc.perform(post("/login")
			.param("username", "not-exist-user-" + UUID.randomUUID().toString().substring(0, 6))
			.param("password", "Whatever123")
			.with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login?error=true"));
	}

	@Test
	@DisplayName("被禁用用户无法登录")
	void disabledUserCannotLogin() throws Exception {
		String username = "login-disabled-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		var user = this.userService.findByUsername(username).orElseThrow();
		this.userService.updateStatus(user.getId(), false, false);

		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login?error=true"));

		this.mockMvc.perform(get("/profile"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login"));
	}

	@Test
	@DisplayName("被锁定用户无法登录")
	void lockedUserCannotLogin() throws Exception {
		String username = "login-locked-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		var user = this.userService.findByUsername(username).orElseThrow();
		this.userService.updateStatus(user.getId(), true, true);

		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login?error=true"));
	}

	@Test
	@DisplayName("邮箱也可以登录")
	void loginWithEmail() throws Exception {
		String username = "login-email-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);

		this.mockMvc.perform(post("/login")
			.param("username", username + "@mao.local")
			.param("password", password)
			.with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/"));
	}

	@Test
	@DisplayName("缺少 CSRF Token 的登录请求被拒绝（403）")
	void loginWithoutCsrfTokenIsRejected() throws Exception {
		String username = "login-csrf-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);

		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password))
			.andExpect(status().isForbidden());
	}

	@Test
	@DisplayName("未认证访问受保护页面重定向到登录页")
	void unauthenticatedAccessRedirectsToLogin() throws Exception {
		this.mockMvc.perform(get("/profile"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login"));
	}

	@Test
	@DisplayName("管理 API 不接受会话认证：无 Bearer Token 一律 401")
	void adminApiRequiresBearerToken() throws Exception {
		String username = "login-admin-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_ADMIN, UserService.ROLE_CUSTOMER);

		MockHttpSession session = new MockHttpSession();
		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.with(csrf())
			.session(session))
			.andExpect(status().is3xxRedirection());

		// 即便会话身份是管理员，管理 API 走的是独立资源服务器链，只认 Bearer Token
		this.mockMvc
			.perform(post("/api/v1/admin/user/page").session(session)
				.contentType(org.springframework.http.MediaType.APPLICATION_JSON)
				.content("{}"))
			.andExpect(status().isUnauthorized());
	}

	@Test
	@DisplayName("退出登录后会话失效并跳转登出结果页")
	void logoutInvalidatesSession() throws Exception {
		String username = "login-logout-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);

		MockHttpSession session = new MockHttpSession();
		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.with(csrf())
			.session(session))
			.andExpect(status().is3xxRedirection());

		this.mockMvc.perform(post("/logout").with(csrf()).session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/logout-success"));

		// 退出后使用新会话访问受保护页面，应被重定向到登录页
		this.mockMvc.perform(get("/profile"))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login"));

		this.mockMvc.perform(get("/logout-success"))
			.andExpect(status().isOk())
			.andExpect(view().name("logout-success"));
	}

	@Test
	@DisplayName("登录页渲染并包含 CSRF 隐藏域")
	void loginPageRendersWithCsrfField() throws Exception {
		MvcResult result = this.mockMvc.perform(get("/login"))
			.andExpect(status().isOk())
			.andExpect(view().name("login"))
			.andExpect(content().string(org.hamcrest.Matchers.containsString("_csrf")))
			.andReturn();
		String html = result.getResponse().getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
		org.assertj.core.api.Assertions.assertThat(html).contains("用户名或邮箱").contains("name=\"username\"");
	}

	@Test
	@DisplayName("登录页返回安全响应头")
	void securityHeadersPresent() throws Exception {
		this.mockMvc.perform(get("/login"))
			.andExpect(status().isOk())
			.andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("default-src 'self'")))
			.andExpect(header().string("X-Frame-Options", "DENY"))
			.andExpect(header().string("X-Content-Type-Options", "nosniff"))
			.andExpect(header().string("Referrer-Policy", "strict-origin-when-cross-origin"));
	}

	@Test
	@DisplayName("CORS 默认拒绝跨域请求")
	void corsDeniesCrossOriginRequests() throws Exception {
		this.mockMvc.perform(get("/login").header(HttpHeaders.ORIGIN, "https://evil.example.com"))
			.andExpect(status().isForbidden());
	}

	@Test
	@DisplayName("同源请求不受 CORS 影响")
	void sameOriginRequestPasses() throws Exception {
		// MockMvc 默认主机为 localhost:80，使用同源 Origin 验证普通请求不受影响
		this.mockMvc.perform(get("/login").header(HttpHeaders.ORIGIN, "http://localhost"))
			.andExpect(status().isOk());
	}

	@Test
	@DisplayName("不安全的登录跳转参数被拒绝")
	void unsafeRedirectParameterIsRejected() throws Exception {
		String username = "login-redir-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);

		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.param("redirect", "https://evil.example.com/phish")
			.with(csrf()))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/"));
	}

}
