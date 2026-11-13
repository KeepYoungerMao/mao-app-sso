package com.mao.sso.api.dto;

import java.time.Instant;
import java.util.List;

import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import com.mao.sso.api.client.ClientService;
import com.mao.sso.domain.account.Role;
import com.mao.sso.domain.account.User;

/**
 * 管理 API 的响应体定义。
 *
 * <p>与领域对象分离的原因：</p>
 * <ul>
 *   <li>绝不能把 {@code passwordHash}、{@code client_secret}（哈希）序列化出去；</li>
 *   <li>客户端实体来自 Spring Authorization Server 的 {@link RegisteredClient}，
 *       直接序列化会输出大量内部结构。</li>
 * </ul>
 */
public final class AdminViews {

	private AdminViews() {
	}

	/** 角色视图。 */
	public record RoleView(Integer id, String code, String name) {

		public static RoleView from(Role role) {
			return new RoleView(role.getId(), role.getCode(), role.getName());
		}

	}

	/** 用户视图（不含任何密码信息）。 */
	public record UserView(Integer id, String username, String email, String phone, String avatar,
			String displayName, boolean enabled, boolean accountLocked, boolean accountExpired,
			boolean mustChangePassword, Instant credentialsExpiredAt, Instant lastLoginAt, Instant createdAt,
			Instant updatedAt, String createdBy, String updatedBy, List<RoleView> roles) {

		public static UserView from(User user) {
			List<RoleView> roles = user.getRoles().stream().map(RoleView::from).toList();
			return new UserView(user.getId(), user.getUsername(), user.getEmail(), user.getPhone(),
					user.getAvatar(), user.getDisplayName(), user.isEnabled(), user.isAccountLocked(),
					user.isAccountExpired(), user.isMustChangePassword(), user.getCredentialsExpiredAt(),
					user.getLastLoginAt(), user.getCreatedAt(), user.getUpdatedAt(), user.getCreatedBy(),
					user.getUpdatedBy(), roles);
		}

	}

	/** 创建用户结果：初始密码只在此响应中出现一次。 */
	public record CreatedUserView(Integer id, String username, String initialPassword) {
	}

	/** 重置密码结果：新密码只在此响应中出现一次。 */
	public record OneTimePasswordView(Integer id, String username, String password) {
	}

	/** 删除结果。 */
	public record DeletedView(Integer id, boolean deleted) {
	}

	/** 客户端视图（不含密钥哈希）。 */
	public record ClientView(String clientId, String clientName,
			List<String> authenticationMethods, List<String> grantTypes, List<String> redirectUris,
			List<String> scopes, boolean requireConsent, boolean requireProofKey, boolean confidential,
			String createdBy, Instant createdAt, String updatedBy, Instant updatedAt) {

		public static ClientView from(ClientService.ClientDetail detail) {
			RegisteredClient client = detail.client();
			List<String> methods = client.getClientAuthenticationMethods()
				.stream()
				.map(ClientAuthenticationMethod::getValue)
				.toList();
			return new ClientView(client.getClientId(), client.getClientName(), methods,
					client.getAuthorizationGrantTypes()
						.stream()
						.map(org.springframework.security.oauth2.core.AuthorizationGrantType::getValue)
						.toList(),
					List.copyOf(client.getRedirectUris()), List.copyOf(client.getScopes()),
					client.getClientSettings().isRequireAuthorizationConsent(),
					client.getClientSettings().isRequireProofKey(), client.getClientSecret() != null,
					detail.createdBy(), detail.createdAt(), detail.updatedBy(), detail.updatedAt());
		}

	}

	/** 创建客户端结果：明文密钥只在此响应中出现一次（公共客户端为 null）。 */
	public record CreatedClientView(String clientId, String clientSecret) {
	}

}
