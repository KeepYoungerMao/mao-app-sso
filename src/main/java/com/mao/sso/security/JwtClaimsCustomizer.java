package com.mao.sso.security;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import com.mao.sso.user.User;
import com.mao.sso.user.UserRepository;

/**
 * JWT Claims 定制：为 Access Token 与 ID Token 添加最小化业务 Claims。
 *
 * <ul>
 *   <li>Access Token：{@code roles}（用户角色码列表，供资源服务器做粗粒度授权）；</li>
 *   <li>ID Token：{@code name}、{@code preferred_username}，email scope 授权时附加
 *       {@code email}、{@code email_verified}。{@code sub} 由框架设置为用户名。</li>
 * </ul>
 *
 * <p>Principal 为 Spring Security 内置 {@link UserDetails}（授权记录持久化要求），
 * 业务属性（id/email/displayName）按用户名从数据库查询补充。</p>
 *
 * <p>UserInfo 端点的默认实现从 ID Token Claims 派生并按 scope 过滤，
 * 因此无需单独实现 UserInfo 映射器。</p>
 *
 * <p>安全约束：绝不写入密码、密码哈希或其他敏感个人信息。</p>
 */
@Component
public class JwtClaimsCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final UserRepository userRepository;

	public JwtClaimsCustomizer(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	public void customize(JwtEncodingContext context) {
		Authentication principal = context.getPrincipal();
		if (principal == null) {
			return;
		}
		String username = principal.getName();
		if (username == null || username.isBlank()) {
			return;
		}
		User user = this.userRepository.findByUsernameWithRoles(username).orElse(null);
		if (user == null) {
			return;
		}
		if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
			// 注意：claims 会被持久化到 oauth2_authorization.access_token_metadata，
			// Spring Security 的 Jackson 多态类型校验仅允许特定集合类型，
			// 因此使用 ArrayList（而非 List.of() 的 ImmutableCollections$ListN）
			List<String> roles = new ArrayList<>(user.getRoles().stream().map((role) -> role.getCode()).toList());
			java.util.Collections.sort(roles);
			context.getClaims().claim("roles", roles);
		}
		else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			context.getClaims().claim("name", user.getDisplayName());
			context.getClaims().claim("preferred_username", user.getUsername());
			if (context.getAuthorizedScopes().contains(OidcScopes.EMAIL)) {
				context.getClaims().claim("email", user.getEmail());
				context.getClaims().claim("email_verified", true);
			}
		}
	}

}
