package com.mao.sso.support;

import java.time.Duration;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import com.mao.sso.user.User;
import com.mao.sso.user.UserService;

/**
 * 测试数据工厂：创建测试用户与 OAuth 客户端（每次测试使用唯一标识，互不干扰）。
 */
public final class TestDataFactory {

	private static final Logger log = LoggerFactory.getLogger(TestDataFactory.class);

	private TestDataFactory() {
	}

	/** 创建测试用户，返回明文密码（测试专用）。 */
	public static String createUser(UserService userService, PasswordEncoder passwordEncoder,
			String username, String... roleCodes) {
		String rawPassword = "Passw0rd-" + UUID.randomUUID().toString().substring(0, 8);
		Set<String> roles = new LinkedHashSet<>(java.util.Arrays.asList(roleCodes));
		if (roles.isEmpty()) {
			roles.add(UserService.ROLE_USER);
		}
		userService.createUser(username, username + "@mao.local", rawPassword, "测试用户 " + username, roles);
		return rawPassword;
	}

	/** 创建保密客户端（client_secret_basic），返回明文密钥。 */
	public static String createConfidentialClient(RegisteredClientRepository repository,
			PasswordEncoder passwordEncoder, String clientId, String redirectUri, boolean requireConsent,
			String... scopes) {
		String rawSecret = "secret-" + UUID.randomUUID().toString().substring(0, 12);
		RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId(clientId)
			.clientIdIssuedAt(java.time.Instant.now())
			.clientSecret(passwordEncoder.encode(rawSecret))
			.clientName("测试客户端 " + clientId)
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUri(redirectUri)
			.scope("openid")
			.scopes((s) -> s.addAll(new LinkedHashSet<>(java.util.Arrays.asList(scopes))))
			.clientSettings(ClientSettings.builder()
				.requireAuthorizationConsent(requireConsent)
				.requireProofKey(true)
				.build())
			.tokenSettings(TokenSettings.builder()
				.accessTokenTimeToLive(Duration.ofMinutes(15))
				.refreshTokenTimeToLive(Duration.ofDays(30))
				.authorizationCodeTimeToLive(Duration.ofMinutes(5))
				.reuseRefreshTokens(false)
				.build())
			.build();
		repository.save(client);
		return rawSecret;
	}

	/** 创建公共客户端（none + 强制 PKCE）。 */
	public static void createPublicClient(RegisteredClientRepository repository, String clientId,
			String redirectUri, boolean requireConsent, String... scopes) {
		RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
			.clientId(clientId)
			.clientIdIssuedAt(java.time.Instant.now())
			.clientName("测试公共客户端 " + clientId)
			.clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
			.redirectUri(redirectUri)
			.scope("openid")
			.scopes((s) -> s.addAll(new LinkedHashSet<>(java.util.Arrays.asList(scopes))))
			.clientSettings(ClientSettings.builder()
				.requireAuthorizationConsent(requireConsent)
				.requireProofKey(true)
				.build())
			.tokenSettings(TokenSettings.builder()
				.accessTokenTimeToLive(Duration.ofMinutes(15))
				.refreshTokenTimeToLive(Duration.ofDays(30))
				.reuseRefreshTokens(false)
				.build())
			.build();
		repository.save(client);
	}

}
