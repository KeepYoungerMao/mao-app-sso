package com.mao.sso.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.UUID;

import com.jayway.jsonpath.JsonPath;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;

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
 * OAuth 2.1 Authorization Code + PKCE(S256) + OIDC 全流程集成测试：
 * 授权请求 → 登录 → 授权确认 → 授权码 → Token 换取 → UserInfo → Refresh Token。
 */
@SpringBootTest
@AutoConfigureMockMvc
class OAuthAuthorizationCodeFlowTest extends IntegrationTestSupport {

	private static final String REDIRECT_URI = "http://localhost/callback";

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	@DisplayName("完整授权码流程：登录 + 授权确认 + PKCE + Token + UserInfo + Refresh")
	void fullAuthorizationCodeFlowWithPkce() throws Exception {
		String clientId = "flow-" + UUID.randomUUID().toString().substring(0, 8);
		String clientSecret = TestDataFactory.createConfidentialClient(this.registeredClientRepository,
				this.passwordEncoder, clientId, REDIRECT_URI, true, "openid", "profile");
		String username = "flow-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		String state = "st-" + UUID.randomUUID();
		PkcePair pkce = generatePkce();

		// 1) 未登录访问授权端点 → 重定向到登录页
		MockHttpSession session = new MockHttpSession();
		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid profile")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", state)
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login"));

		// 2) 登录 → 重定向回授权端点（登录前保存的请求，OAuth 2.1 授权流程依赖此行为）
		this.mockMvc.perform(post("/login")
			.param("username", username)
			.param("password", password)
			.with(csrf())
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(result -> {
				// saved request URL 为绝对地址（Spring Security 7 行为），校验路径与参数
				String location = result.getResponse().getRedirectedUrl();
				assertThat(location).contains("/oauth2/authorize");
				assertThat(queryParameter(location, "client_id")).isEqualTo(clientId);
				assertThat(queryParameter(location, "code_challenge")).isNotBlank();
			});

		// 3) 再次访问授权端点 → 需要授权确认（requireAuthorizationConsent=true）。
		// 注意：框架此时会生成新的 consent state，授权确认页提交必须使用该 state
		MvcResult consentRedirect = this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid profile")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", state)
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andExpect(result -> {
				String location = result.getResponse().getRedirectedUrl();
				assertThat(location).startsWith("http://localhost/oauth2/consent");
				assertThat(queryParameter(location, "client_id")).isEqualTo(clientId);
			})
			.andReturn();
		String consentState = queryParameter(consentRedirect.getResponse().getRedirectedUrl(), "state");
		assertThat(consentState).isNotBlank();

		// 4) 授权确认页渲染
		this.mockMvc.perform(get("/oauth2/consent")
			.param("client_id", clientId)
			.param("scope", "openid profile")
			.param("state", consentState)
			.session(session))
			.andExpect(status().isOk())
			.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.view().name("consent"))
			.andExpect(org.springframework.test.web.servlet.result.MockMvcResultMatchers.model()
				.attribute("clientId", clientId));

		// 5) 提交授权确认（使用 consent state）→ 重定向回客户端并携带授权码
		MvcResult consentResult = this.mockMvc.perform(post("/oauth2/authorize")
			.param("client_id", clientId)
			.param("state", consentState)
			.param("scope", "openid", "profile")
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String consentLocation = consentResult.getResponse().getRedirectedUrl();
		assertThat(consentLocation).startsWith(REDIRECT_URI);
		assertThat(queryParameter(consentLocation, "state")).isEqualTo(state);
		String authorizationCode = queryParameter(consentLocation, "code");
		assertThat(authorizationCode).isNotBlank();

		// 6) 授权码 + PKCE 换取 Token
		MvcResult tokenResult = this.mockMvc.perform(post("/oauth2/token")
			.header(HttpHeaders.AUTHORIZATION, basicAuth(clientId, clientSecret))
			.param("grant_type", "authorization_code")
			.param("code", authorizationCode)
			.param("redirect_uri", REDIRECT_URI)
			.param("code_verifier", pkce.codeVerifier()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.token_type").value("Bearer"))
			.andExpect(jsonPath("$.expires_in").isNumber())
			.andReturn();
		TokenResponse tokens = parseTokenResponse(tokenResult);
		assertThat(tokens.accessToken()).isNotBlank();
		assertThat(tokens.refreshToken()).isNotBlank();
		assertThat(tokens.idToken()).isNotBlank();

		// 7) Access Token 为 JWT，Claims 合理且不含敏感信息
		SignedJWT accessJwt = SignedJWT.parse(tokens.accessToken());
		RSAKey jwk = jwkFromJwksEndpoint();
		assertThat(accessJwt.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(jwk.toRSAPublicKey()))).isTrue();
		assertThat(accessJwt.getJWTClaimsSet().getSubject()).isEqualTo(username);
		assertThat(accessJwt.getJWTClaimsSet().getIssuer()).isEqualTo("http://localhost:8080");
		assertThat(accessJwt.getJWTClaimsSet().getStringListClaim("roles")).contains("customer");
		assertThat(accessJwt.getJWTClaimsSet().getClaims().keySet())
			.doesNotContain("password", "password_hash", "email");

		// 8) ID Token 包含 OIDC 标准 Claims（仅 openid + profile 两个 scope）
		SignedJWT idJwt = SignedJWT.parse(tokens.idToken());
		assertThat(idJwt.verify(new com.nimbusds.jose.crypto.RSASSAVerifier(jwk.toRSAPublicKey()))).isTrue();
		assertThat(idJwt.getJWTClaimsSet().getAudience()).containsExactly(clientId);
		assertThat(idJwt.getJWTClaimsSet().getSubject()).isEqualTo(username);
		assertThat(idJwt.getJWTClaimsSet().getStringClaim("name")).isNotBlank();
		assertThat(idJwt.getJWTClaimsSet().getStringClaim("preferred_username")).isEqualTo(username);
		// 未申请 email scope，因此不得出现邮箱相关 claim
		assertThat(idJwt.getJWTClaimsSet().getClaims().keySet()).doesNotContain("email", "email_verified");

		// 9) UserInfo 端点（按 scope 裁剪：profile 提供 name，不提供 email）
		this.mockMvc.perform(get("/userinfo").header(HttpHeaders.AUTHORIZATION, "Bearer " + tokens.accessToken()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.sub").value(username))
			.andExpect(jsonPath("$.name").isString())
			.andExpect(jsonPath("$.email").doesNotExist());

		// 10) Refresh Token 换取新 Token（轮换）
		MvcResult refreshResult = this.mockMvc.perform(post("/oauth2/token")
			.header(HttpHeaders.AUTHORIZATION, basicAuth(clientId, clientSecret))
			.param("grant_type", "refresh_token")
			.param("refresh_token", tokens.refreshToken()))
			.andExpect(status().isOk())
			.andReturn();
		TokenResponse refreshed = parseTokenResponse(refreshResult);
		assertThat(refreshed.accessToken()).isNotBlank();
		assertThat(refreshed.refreshToken()).isNotEqualTo(tokens.refreshToken());

		// 11) 旧 Refresh Token 已失效（轮换后不可复用）
		this.mockMvc.perform(post("/oauth2/token")
			.header(HttpHeaders.AUTHORIZATION, basicAuth(clientId, clientSecret))
			.param("grant_type", "refresh_token")
			.param("refresh_token", tokens.refreshToken()))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_grant"));
	}

	@Test
	@DisplayName("无需重复授权的客户端：登录后直接颁发授权码")
	void authorizationCodeWithoutConsentPage() throws Exception {
		String clientId = "noconsent-" + UUID.randomUUID().toString().substring(0, 8);
		String clientSecret = TestDataFactory.createConfidentialClient(this.registeredClientRepository,
				this.passwordEncoder, clientId, REDIRECT_URI, false, "openid");
		String username = "noconsent-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		String state = "st-" + UUID.randomUUID();
		PkcePair pkce = generatePkce();

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

		MvcResult authorizeResult = this.mockMvc.perform(get("/oauth2/authorize")
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
		String location = authorizeResult.getResponse().getRedirectedUrl();
		assertThat(location).startsWith(REDIRECT_URI);
		assertThat(queryParameter(location, "code")).isNotBlank();
	}

	@Test
	@DisplayName("公共客户端（无密钥）+ PKCE 完成授权码流程")
	void publicClientFlowWithPkce() throws Exception {
		String clientId = "pub-" + UUID.randomUUID().toString().substring(0, 8);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, REDIRECT_URI, false,
				"openid", "profile");
		String username = "pub-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		String state = "st-" + UUID.randomUUID();
		PkcePair pkce = generatePkce();

		MockHttpSession session = new MockHttpSession();
		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid profile")
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

		MvcResult authorizeResult = this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", "openid profile")
			.param("redirect_uri", REDIRECT_URI)
			.param("state", state)
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		String code = queryParameter(authorizeResult.getResponse().getRedirectedUrl(), "code");
		assertThat(code).isNotBlank();

		// 公共客户端不带客户端密钥，仅 PKCE 证明。
		// 自定义 PublicClientRefreshTokenGenerator 允许为公共客户端签发 refresh token
		// （官方 OAuth2RefreshTokenGenerator 直接跳过），MCP 客户端依赖它静默续期。
		MvcResult tokenResult = this.mockMvc.perform(post("/oauth2/token")
			.param("grant_type", "authorization_code")
			.param("code", code)
			.param("redirect_uri", REDIRECT_URI)
			.param("client_id", clientId)
			.param("code_verifier", pkce.codeVerifier()))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isString())
			.andExpect(jsonPath("$.refresh_token").isString())
			.andReturn();
		TokenResponse tokens = parseTokenResponse(tokenResult);

		// 公共客户端凭 refresh token（+ client_id，无密钥）静默续期；
		// 测试客户端 reuseRefreshTokens=false，续期会轮换出新 refresh token
		MvcResult refreshResult = this.mockMvc.perform(post("/oauth2/token")
			.param("grant_type", "refresh_token")
			.param("refresh_token", tokens.refreshToken())
			.param("client_id", clientId))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isString())
			.andReturn();
		TokenResponse refreshed = parseTokenResponse(refreshResult);
		assertThat(refreshed.refreshToken()).isNotEqualTo(tokens.refreshToken());
	}

	@Test
	@DisplayName("授权码一次性有效：重复使用返回 invalid_grant")
	void authorizationCodeIsSingleUse() throws Exception {
		String clientId = "single-" + UUID.randomUUID().toString().substring(0, 8);
		String clientSecret = TestDataFactory.createConfidentialClient(this.registeredClientRepository,
				this.passwordEncoder, clientId, REDIRECT_URI, false, "openid");
		String username = "single-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		PkcePair pkce = generatePkce();
		String code = obtainAuthorizationCode(clientId, username, password, "openid", pkce, null);

		this.mockMvc.perform(post("/oauth2/token")
			.header(HttpHeaders.AUTHORIZATION, basicAuth(clientId, clientSecret))
			.param("grant_type", "authorization_code")
			.param("code", code)
			.param("redirect_uri", REDIRECT_URI)
			.param("code_verifier", pkce.codeVerifier()))
			.andExpect(status().isOk());

		this.mockMvc.perform(post("/oauth2/token")
			.header(HttpHeaders.AUTHORIZATION, basicAuth(clientId, clientSecret))
			.param("grant_type", "authorization_code")
			.param("code", code)
			.param("redirect_uri", REDIRECT_URI)
			.param("code_verifier", pkce.codeVerifier()))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_grant"));
	}

	@Test
	@DisplayName("错误 code_verifier 返回 invalid_grant")
	void wrongCodeVerifierRejected() throws Exception {
		String clientId = "badverifier-" + UUID.randomUUID().toString().substring(0, 8);
		String clientSecret = TestDataFactory.createConfidentialClient(this.registeredClientRepository,
				this.passwordEncoder, clientId, REDIRECT_URI, false, "openid");
		String username = "badverifier-user-" + UUID.randomUUID().toString().substring(0, 6);
		String password = TestDataFactory.createUser(this.userService, this.passwordEncoder, username,
				UserService.ROLE_CUSTOMER);
		PkcePair pkce = generatePkce();
		String code = obtainAuthorizationCode(clientId, username, password, "openid", pkce, null);

		PkcePair other = generatePkce();
		this.mockMvc.perform(post("/oauth2/token")
			.header(HttpHeaders.AUTHORIZATION, basicAuth(clientId, clientSecret))
			.param("grant_type", "authorization_code")
			.param("code", code)
			.param("redirect_uri", REDIRECT_URI)
			.param("code_verifier", other.codeVerifier()))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_grant"));
	}

	// ---------- 辅助方法 ----------

	private String obtainAuthorizationCode(String clientId, String username, String password, String scope,
			PkcePair pkce, String state) throws Exception {
		String resolvedState = (state != null) ? state : "st-" + UUID.randomUUID();
		MockHttpSession session = new MockHttpSession();
		this.mockMvc.perform(get("/oauth2/authorize")
			.param("response_type", "code")
			.param("client_id", clientId)
			.param("scope", scope)
			.param("redirect_uri", REDIRECT_URI)
			.param("state", resolvedState)
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
			.param("scope", scope)
			.param("redirect_uri", REDIRECT_URI)
			.param("state", resolvedState)
			.param("code_challenge", pkce.codeChallenge())
			.param("code_challenge_method", "S256").with(syncQueryString()).accept(MediaType.TEXT_HTML)
			.session(session))
			.andExpect(status().is3xxRedirection())
			.andReturn();
		return queryParameter(result.getResponse().getRedirectedUrl(), "code");
	}

	private RSAKey jwkFromJwksEndpoint() throws Exception {
		MvcResult result = this.mockMvc.perform(get("/oauth2/jwks"))
			.andExpect(status().isOk())
			.andReturn();
		String json = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
		JWKSet jwkSet = JWKSet.parse(json);
		return (RSAKey) jwkSet.getKeys().get(0);
	}

	private static TokenResponse parseTokenResponse(MvcResult result) throws Exception {
		String json = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
		return new TokenResponse(JsonPath.read(json, "$.access_token"), JsonPath.read(json, "$.refresh_token"),
				JsonPath.read(json, "$.id_token"));
	}

	private record TokenResponse(String accessToken, String refreshToken, String idToken) {
	}

	private static String basicAuth(String clientId, String clientSecret) {
		String credentials = clientId + ":" + clientSecret;
		return "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
	}

}
