package com.mao.sso.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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

import com.mao.sso.support.IntegrationTestSupport;

/**
 * 动态客户端注册（RFC 7591 / OIDC Client Registration）端点测试。
 *
 * <p>覆盖：两个端点均可用、元数据对外宣告注册端点、白名单护栏、
 * 以及注册后强制 PKCE / 授权确认。</p>
 */
@SpringBootTest
@AutoConfigureMockMvc
class DynamicClientRegistrationTest extends IntegrationTestSupport {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Test
	@DisplayName("RFC 7591 端点 /oauth2/register 可注册 public client")
	void registerPublicClient() throws Exception {
		String body = registrationJson("dcr-oauth-client", List.of("http://localhost:9000/callback"),
				"openid profile", "none");
		String response = this.mockMvc
			.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.client_id").isString())
			.andExpect(jsonPath("$.client_id_issued_at").isNumber())
			.andExpect(jsonPath("$.redirect_uris[0]").value("http://localhost:9000/callback"))
			.andReturn()
			.getResponse()
			.getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
		assertThat(response).doesNotContain("client_secret");
	}

	@Test
	@DisplayName("MCP 场景的自定义 scheme 与业务 scope 可正常注册")
	void mcpStyleClientCanRegister() throws Exception {
		String body = registrationJson("scnet-ocr-recognition",
				List.of("workbuddy://workbuddy/mcp/custom-mcp%3Ascnet-ocr-recognition/oauth/callback"),
				"userId userInfo aksk mcp:read", "none");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isCreated())
			.andExpect(jsonPath("$.client_id").isString());
	}

	@Test
	@DisplayName("OIDC 注册端点 /connect/register 不启用（SAS 实现强制要求 initial access token）")
	void oidcRegistrationEndpointIsNotEnabled() throws Exception {
		String body = registrationJson("dcr-oidc", List.of("http://localhost:9000/callback"), "openid", "none");
		this.mockMvc.perform(post("/connect/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().is4xxClientError());
	}

	@Test
	@DisplayName("注册成功后强制开启 PKCE 与授权确认（OAuth 2.1 约束）")
	void registeredClientIsForcedToUsePkce() throws Exception {
		String body = registrationJson("dcr-pkce-client", List.of("http://localhost:9000/callback"), "openid",
				"none");
		String response = this.mockMvc
			.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isCreated())
			.andReturn()
			.getResponse()
			.getContentAsString(java.nio.charset.StandardCharsets.UTF_8);
		String clientId = com.jayway.jsonpath.JsonPath.read(response, "$.client_id");
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
	@DisplayName("不在白名单的 scope 被拒绝")
	void scopeOutsideAllowListIsRejected() throws Exception {
		String body = registrationJson("dcr-bad-scope", List.of("http://localhost:9000/callback"), "root admin",
				"none");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_scope"));
	}

	@Test
	@DisplayName("通配符 redirect_uri 被拒绝（防开放重定向）")
	void wildcardRedirectUriIsRejected() throws Exception {
		String body = registrationJson("dcr-wildcard", List.of("https://*.example.com/callback"), "openid",
				"none");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_redirect_uri"));
	}

	@Test
	@DisplayName("非本机 http redirect_uri 被拒绝")
	void remoteHttpRedirectUriIsRejected() throws Exception {
		String body = registrationJson("dcr-remote-http", List.of("http://attacker.example.com/callback"),
				"openid", "none");
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
	@DisplayName("不允许的 grant_type 被拒绝")
	void disallowedGrantTypeIsRejected() throws Exception {
		String body = """
				{"client_name":"dcr-cc","redirect_uris":["http://localhost:9000/callback"],\
				"grant_types":["client_credentials"],"response_types":["code"],\
				"token_endpoint_auth_method":"none","scope":"openid"}
				""";
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_request"));
	}

	@Test
	@DisplayName("不允许的 token_endpoint_auth_method 被拒绝")
	void disallowedAuthenticationMethodIsRejected() throws Exception {
		String body = registrationJson("dcr-pkjwt", List.of("http://localhost:9000/callback"), "openid",
				"private_key_jwt");
		this.mockMvc.perform(post("/oauth2/register").contentType(MediaType.APPLICATION_JSON).content(body))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.error").value("invalid_request"));
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
