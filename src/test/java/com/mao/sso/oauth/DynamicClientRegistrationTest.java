package com.mao.sso.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import com.jayway.jsonpath.JsonPath;
import com.mao.sso.support.IntegrationTestSupport;
import com.mao.sso.support.TestDataFactory;

/**
 * 动态客户端注册（RFC 7591）端点测试。
 *
 * <h3>本服务的 DCR 语义：预录入 + 查表返回</h3>
 * <p>客户端不允许通过 DCR 自助创建，必须先在管理后台（{@code /api/v1/admin/client/create}）
 * 录入。DCR 端点收到注册请求后按 {@code redirect_uris} 精确查表，命中则返回<b>预录入的固定
 * client_id</b>，全程不 INSERT 新记录；未命中的 {@code redirect_uri} 一律 400
 * {@code invalid_redirect_uri}。请求中的 grant_type / scope / response_type /
 * token_endpoint_auth_method 不得超出预录入范围。</p>
 *
 * <p>因此下面每个用例都先用 {@link TestDataFactory} 造出预录入客户端，再验证 DCR 的返回
 * 与护栏；断言「不改配置、不建新客户端」是本端点最重要的不变量。</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
class DynamicClientRegistrationTest extends IntegrationTestSupport {

	/**
	 * 每个客户端使用<b>唯一</b>的 redirect_uri。
	 *
	 * <p>DCR 按 redirect_uri 反查客户端（不要求全局唯一），同名回调用例之间会互相串到
	 * 对方的客户端上，因此这里按 client_id 派生。</p>
	 */
	private static String redirectUriFor(String clientId) {
		return "http://localhost:9000/" + clientId + "/callback";
	}

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	@DisplayName("预录入的 public client 可通过 /oauth2/register 换取固定 client_id")
	void registerPublicClient() throws Exception {
		String clientId = "dcr-oauth-client";
		String redirectUri = redirectUriFor(clientId);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, redirectUri, true, "profile");

		String body = registrationJson("dcr-oauth-client", List.of(redirectUri), "openid profile", "none");
		String response = this.mockMvc
			.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.client_id").value(clientId))
			.andExpect(jsonPath("$.client_id_issued_at").isNumber())
			.andExpect(jsonPath("$.redirect_uris[0]").value(redirectUri))
			.andReturn()
			.getResponse()
			.getContentAsString(StandardCharsets.UTF_8);
		// public client 不应下发密钥
		assertThat(response).doesNotContain("client_secret");

		// 重复注册必须返回同一个 client_id（不 INSERT 新记录）
		String again = this.mockMvc
			.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isCreated())
			.andReturn()
			.getResponse()
			.getContentAsString(StandardCharsets.UTF_8);
		assertThat((String) JsonPath.read(again, "$.client_id")).isEqualTo(clientId);
	}

	@Test
	@DisplayName("MCP 场景：自定义 scheme 可作为 redirect_uri 预录入并被 DCR 命中")
	void mcpStyleClientCanRegister() throws Exception {
		String customRedirect = "workbuddy://workbuddy/mcp/custom-mcp%3Ascnet-ocr-recognition/oauth/callback";
		String clientId = "scnet-ocr-recognition";
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, customRedirect, true, "userId",
				"userInfo", "aksk", "mcp:read");

		String body = registrationJson(clientId, List.of(customRedirect), "userId userInfo aksk mcp:read", "none");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.client_id").value(clientId))
			.andExpect(jsonPath("$.redirect_uris[0]").value(customRedirect));
	}

	@Test
	@DisplayName("未预录入的 redirect_uri 被拒绝（不允许自助创建客户端）")
	void unregisteredRedirectUriIsRejected() throws Exception {
		String body = registrationJson("dcr-unknown",
				List.of("http://localhost:9100/never-registered"), "openid", "none");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_redirect_uri"));
	}

	@Test
	@DisplayName("DCR 不会放宽预录入的安全设置（强制 PKCE + 授权确认）")
	void registeredClientIsForcedToUsePkce() throws Exception {
		String clientId = "dcr-pkce-client";
		String redirectUri = redirectUriFor(clientId);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, redirectUri, true);

		String body = registrationJson(clientId, List.of(redirectUri), "openid", "none");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.client_id").value(clientId));

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId(clientId);
		assertThat(registeredClient).isNotNull();
		assertThat(registeredClient.getClientSettings().isRequireProofKey()).isTrue();
		assertThat(registeredClient.getClientSettings().isRequireAuthorizationConsent()).isTrue();
	}

	@Test
	@DisplayName("授权服务器元数据宣告 registration_endpoint")
	void metadataAdvertisesRegistrationEndpoint() throws Exception {
		this.mockMvc.perform(get("/.well-known/oauth-authorization-server"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.registration_endpoint").isString());
	}

	@Test
	@DisplayName("请求的 scope 超出预录入范围被拒绝")
	void scopeOutsideAllowListIsRejected() throws Exception {
		String clientId = "dcr-bad-scope";
		String redirectUri = redirectUriFor(clientId);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, redirectUri, false);

		String body = registrationJson(clientId, List.of(redirectUri), "openid root", "none");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_scope"));
	}

	@Test
	@DisplayName("通配符 redirect_uri 被拒绝（防开放重定向）")
	void wildcardRedirectUriIsRejected() throws Exception {
		String body = registrationJson("dcr-wildcard", List.of("https://*.example.com/callback"), "openid", "none");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_redirect_uri"));
	}

	@Test
	@DisplayName("缺少 redirect_uris 被拒绝")
	void missingRedirectUrisIsRejected() throws Exception {
		String body = """
				{"client_name":"dcr-no-redirect","grant_types":["authorization_code"],\
				"response_types":["code"],"token_endpoint_auth_method":"none","scope":"openid"}
				""";
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_redirect_uri"));
	}

	@Test
	@DisplayName("请求的 grant_type 超出预录入范围被拒绝")
	void disallowedGrantTypeIsRejected() throws Exception {
		String clientId = "dcr-cc";
		String redirectUri = redirectUriFor(clientId);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, redirectUri, false);

		String body = """
				{"client_name":"%s","redirect_uris":["%s"],\
				"grant_types":["client_credentials"],"response_types":["code"],\
				"token_endpoint_auth_method":"none","scope":"openid"}
				""".formatted(clientId, redirectUri);
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_request"));
	}

	@Test
	@DisplayName("请求的 token_endpoint_auth_method 与预录入不一致时被拒绝")
	void disallowedAuthenticationMethodIsRejected() throws Exception {
		String clientId = "dcr-pkjwt";
		String redirectUri = redirectUriFor(clientId);
		TestDataFactory.createPublicClient(this.registeredClientRepository, clientId, redirectUri, false);

		String body = registrationJson(clientId, List.of(redirectUri), "openid", "private_key_jwt");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_request"));
	}

	@Test
	@DisplayName("OIDC 注册端点 /connect/register 不启用（SAS 实现强制要求 initial access token）")
	void oidcRegistrationEndpointIsNotEnabled() throws Exception {
		String body = registrationJson("dcr-oidc", List.of(redirectUriFor("dcr-oidc")), "openid", "none");
		this.mockMvc.perform(post("/connect/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().is4xxClientError());
	}

	private static String registrationJson(String clientName, List<String> redirectUris, String scope,
			String authMethod) {
		return """
				{"client_name":"%s","redirect_uris":%s,"grant_types":["authorization_code","refresh_token"],\
				"response_types":["code"],"token_endpoint_auth_method":"%s","scope":"%s"}
				"""
			.formatted(clientName, redirectUris.stream().map((uri) -> "\"" + uri + "\"").toList().toString(),
					authMethod, scope);
	}

}
