package com.mao.sso.auth.filter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.mao.sso.support.IntegrationTestSupport;
import com.mao.sso.support.TestDataFactory;
import com.mao.sso.api.user.UserService;

/**
 * 自定义协议重定向中间页（{@link CustomSchemeRedirectFilter}）测试。
 *
 * <p>覆盖：授权确认页 POST 提交后，重定向到自定义协议时渲染中间页（而非被浏览器
 * 静默丢弃的 302）；http(s) 重定向与 GET 直达路径保持原样；中间页链接中的授权码
 * 可正常换取 token。</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
class CustomSchemeRedirectTest extends IntegrationTestSupport {

	private static final String CUSTOM_REDIRECT = "workbuddy://workbuddy/mcp/custom-mcp%3Ascnet-ocr-recognition/oauth/callback";

	private static final String HTTP_REDIRECT = "http://localhost/callback";

	private static final Pattern INTERSTITIAL_LINK = Pattern.compile("href=\"(workbuddy://[^\"]+)\"");

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	@DisplayName("自定义协议判定：http(s) 与相对地址为 false，其余绝对协议为 true")
	void isCustomSchemeRecognizesCustomSchemes() {
		assertThat(CustomSchemeRedirectFilter.isCustomScheme(
				"workbuddy://workbuddy/mcp/custom-mcp%3Ascnet-ocr-recognition/oauth/callback")).isTrue();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme("com.mao.app:/oauth2redirect")).isTrue();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme("myapp+ext://host/path?code=1")).isTrue();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme("MAILTO:a@b.c")).isTrue();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme("http://localhost/callback")).isFalse();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme("HTTPS://example.com/callback")).isFalse();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme("/relative/path")).isFalse();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme("//host/path")).isFalse();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme("")).isFalse();
		assertThat(CustomSchemeRedirectFilter.isCustomScheme(null)).isFalse();
	}

	@Test
	@DisplayName("授权确认提交后跳自定义协议：返回中间页（200）而非 302，链接中的授权码可换 token")
	void consentPostToCustomSchemeRendersInterstitial() throws Exception {
		String clientId = "csr-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, CUSTOM_REDIRECT, true, "openid",
				"profile");
		String username = "csr-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		PkcePair pkce = generatePkce();

		MockHttpSession session = new MockHttpSession();
		String consentState = loginAndReachConsentPage(session, clientId, CUSTOM_REDIRECT, username, password, pkce,
				"openid profile");

		// 提交授权确认（等价于授权页原生表单 POST）
		MvcResult consentResult = this.mockMvc.perform(post("/oauth2/authorize")
			.param("client_id", clientId)
			.param("state", consentState)
			.param("scope", "openid", "profile")
			.session(session))
			.andExpect(status().isOk())
			.andReturn();
		String html = consentResult.getResponse().getContentAsString(StandardCharsets.UTF_8);

		// 中间页：说明 + 指向 workbuddy:// 的普通链接（用户点击后浏览器才会放行协议跳转）
		assertThat(html).contains("授权成功");
		Matcher matcher = INTERSTITIAL_LINK.matcher(html);
		assertThat(matcher.find()).isTrue();
		String redirectUrl = matcher.group(1);
		assertThat(redirectUrl).startsWith(CUSTOM_REDIRECT + "?");
		assertThat(queryParameter(redirectUrl, "code")).isNotBlank();
		// CSP 合规：无内联脚本与样式（script-src/style-src 均为 'self'）
		assertThat(html).doesNotContain("<script").doesNotContain("style=");

		// 中间页链接中的授权码可正常换取 token：证明中间页没有破坏授权码流程
		this.mockMvc.perform(post("/oauth2/token")
			.param("grant_type", "authorization_code")
			.param("code", queryParameter(redirectUrl, "code"))
			.param("redirect_uri", CUSTOM_REDIRECT)
			.param("client_id", clientId)
			.param("code_verifier", pkce.codeVerifier()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isString())
			.andExpect(jsonPath("$.refresh_token").isString());
	}

	@Test
	@DisplayName("授权确认提交后跳 http(s) 地址：保持 302 重定向，不渲染中间页")
	void consentPostToHttpRedirectStillRedirects() throws Exception {
		String clientId = "csr-http-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, HTTP_REDIRECT, true, "openid",
				"profile");
		String username = "csr-http-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		PkcePair pkce = generatePkce();

		MockHttpSession session = new MockHttpSession();
		String consentState = loginAndReachConsentPage(session, clientId, HTTP_REDIRECT, username, password, pkce,
				"openid profile");

		this.mockMvc.perform(post("/oauth2/authorize")
			.param("client_id", clientId)
			.param("state", consentState)
			.param("scope", "openid", "profile")
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(result -> assertThat(result.getResponse().getRedirectedUrl()).startsWith(HTTP_REDIRECT));
	}

	@Test
	@DisplayName("已同意后 GET 直达授权端点跳自定义协议：保持 302（验证可用的路径不被破坏）")
	void directGetToCustomSchemeStillRedirects() throws Exception {
		String clientId = "csr-get-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, CUSTOM_REDIRECT, true, "openid",
				"profile");
		String username = "csr-get-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		PkcePair pkce = generatePkce();

		MockHttpSession session = new MockHttpSession();
		String consentState = loginAndReachConsentPage(session, clientId, CUSTOM_REDIRECT, username, password, pkce,
				"openid profile");
		// 先完成一次授权确认（记录 consent），走中间页
		this.mockMvc.perform(post("/oauth2/authorize")
			.param("client_id", clientId)
			.param("state", consentState)
			.param("scope", "openid", "profile")
			.session(session))
			.andExpect(status().isOk());

		// 已同意：GET 直达授权端点应直接 302 到 workbuddy://（本过滤器只拦截 POST）
		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid")
			.param("redirect_uri", CUSTOM_REDIRECT)
			.param("state", "st-" + UUID.randomUUID())
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256")
			.with(syncQueryString())
			.accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(result -> assertThat(result.getResponse().getRedirectedUrl())
				.startsWith(CUSTOM_REDIRECT + "?"));
	}

	@Test
	@DisplayName("拒绝授权后跳自定义协议：中间页展示错误态并带上 error=access_denied")
	void denyPostToCustomSchemeRendersInterstitial() throws Exception {
		String clientId = "csr-deny-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, CUSTOM_REDIRECT, true, "openid",
				"profile");
		String username = "csr-deny-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		PkcePair pkce = generatePkce();

		MockHttpSession session = new MockHttpSession();
		String consentState = loginAndReachConsentPage(session, clientId, CUSTOM_REDIRECT, username, password, pkce,
				"openid profile");

		// 拒绝授权 = 提交空的 scope 列表（授权页「拒绝授权」按钮的行为）
		MvcResult denyResult = this.mockMvc.perform(post("/oauth2/authorize")
			.param("client_id", clientId)
			.param("state", consentState)
			.session(session))
			.andExpect(status().isOk())
			.andReturn();
		String html = denyResult.getResponse().getContentAsString(StandardCharsets.UTF_8);
		assertThat(html).contains("授权未完成");
		Matcher matcher = INTERSTITIAL_LINK.matcher(html);
		assertThat(matcher.find()).isTrue();
		assertThat(matcher.group(1)).contains("error=access_denied");
	}

	/**
	 * 登录并走到授权确认页，返回授权页表单需要使用的 consent state。
	 *
	 * <p>注意：SAS 7.1 的默认策略下，仅请求 {@code openid} 单个 scope 时跳过授权确认页
	 * （见 {@code OAuth2AuthorizationCodeRequestAuthenticationProvider
	 * #isAuthorizationConsentRequired}），因此本类用例一律请求 2 个及以上 scope，
	 * 与 WorkBuddy 实际请求 {@code openid profile email} 的场景一致。</p>
	 */
	private String loginAndReachConsentPage(MockHttpSession session, String clientId, String redirectUri,
			String username, String password, PkcePair pkce, String scope) throws Exception {
		// 未登录访问授权端点 → 重定向到登录页
		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", scope)
			.param("redirect_uri", redirectUri)
			.param("state", "st-" + UUID.randomUUID())
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256")
			.with(syncQueryString())
			.accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection());

		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf())
			.session(session))
			.andExpect(status().is3xxRedirection());

		// 已登录访问授权端点 → 重定向到授权确认页（框架生成新的 consent state）
		MvcResult consentRedirect = this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", scope)
			.param("redirect_uri", redirectUri)
			.param("state", "st-" + UUID.randomUUID())
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256")
			.with(syncQueryString())
			.accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String location = consentRedirect.getResponse().getRedirectedUrl();
		assertThat(location).startsWith("http://localhost/oauth2/consent");
		return queryParameter(location, "state");
	}

}
