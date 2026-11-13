package com.mao.sso.auth.token;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import com.mao.sso.domain.account.User;
import com.mao.sso.api.user.UserService;

/**
 * JWT Claims 定制：为 Access Token 与 ID Token 添加最小化业务 Claims。
 *
 * <ul>
 *   <li>Access Token：{@code roles}（用户角色 code 列表，如 {@code ["admin"]}，
 *       供资源服务器/管理 API 做授权——本项目<b>按角色授权，不按 scope</b>）；</li>
 *   <li>ID Token：{@code name}、{@code preferred_username}。{@code sub} 由框架设置为用户名。</li>
 * </ul>
 *
 * <p>本项目只定义 {@code openid} / {@code profile} 两个 scope，{@code profile} 决定
 * ID Token 是否携带 {@code name} / {@code preferred_username}（由框架的 scope 裁剪负责），
 * 因此这里不需要额外按 scope 分支。</p>
 *
 * <p>Principal 为 Spring Security 内置 {@link UserDetails}（授权记录持久化要求），
 * 业务属性（id/email/displayName）按用户名经 {@code UserService} 查询补充。</p>
 *
 * <p>UserInfo 端点的默认实现从 ID Token Claims 派生并按 scope 过滤，
 * 因此无需单独实现 UserInfo 映射器。</p>
 *
 * <p>安全约束：绝不写入密码、密码哈希或其他敏感个人信息。</p>
 */
@Component
public class JwtClaimsCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

	private final UserService userService;

	public JwtClaimsCustomizer(UserService userService) {
		this.userService = userService;
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
		User user = this.userService.findByUsernameWithRoles(username).orElse(null);
		if (user == null) {
			return;
		}
		if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
			// 注意：claims 会被持久化到 oauth2_authorization.access_token_metadata，
			// Spring Security 的 Jackson 多态类型校验仅允许特定集合类型，
			// 因此使用 ArrayList（而非 List.of() 的 ImmutableCollections$ListN）
			List<String> roles = new ArrayList<>(user.getRoleCodes());
			java.util.Collections.sort(roles);
			context.getClaims().claim("roles", roles);
		}
		else if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
			// 仅 openid / profile 两个 scope，profile 携带身份画像
			if (context.getAuthorizedScopes().contains(OidcScopes.PROFILE)) {
				context.getClaims().claim("name", user.getDisplayName());
				context.getClaims().claim("preferred_username", user.getUsername());
			}
		}
	}

}
