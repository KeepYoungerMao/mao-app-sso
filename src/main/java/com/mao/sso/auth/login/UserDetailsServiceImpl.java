package com.mao.sso.auth.login;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mao.sso.api.user.UserService;

/**
 * 基于数据库的 UserDetailsService。用户名或邮箱均可登录。
 *
 * <h3>为什么使用 Spring Security 内置 User 作为 Principal</h3>
 * <p>OAuth 授权记录（oauth2_authorization.attributes）中的 Principal 需要被
 * Jackson 序列化/反序列化（JdbcOAuth2AuthorizationService）。Spring Security 的
 * {@code CoreJacksonModule} 配置了多态类型校验白名单，仅允许框架内置类型
 * （含 {@link org.springframework.security.core.userdetails.User}，官方提供
 * UserMixin 支持完整往返）。自定义 UserDetails 实现会被反序列化拒绝，
 * 导致授权码换取 Token 失败。</p>
 *
 * <p>因此 Principal 使用内置 User，业务属性（id/email/displayName）在需要时
 * 按用户名查询数据库获得（见 JwtClaimsCustomizer 与各 Controller）。</p>
 *
 * <h3>四个账户状态位的来源</h3>
 * <ul>
 *   <li>{@code enabled} / {@code accountLocked} / {@code accountExpired}：直接取自用户表；</li>
 *   <li>{@code credentialsExpired}：由 {@code credentials_expired_at} 派生
 *       （为空表示永不过期）——密码到期后登录直接被拒绝。</li>
 * </ul>
 *
 * <p>注意：认证失败信息不区分“用户不存在”与“密码错误”，
 * 由登录失败处理器统一返回通用提示，防止用户枚举。</p>
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	private final UserService userService;

	public UserDetailsServiceImpl(UserService userService) {
		this.userService = userService;
	}

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		return this.userService.findByIdentifier(username)
			.map((user) -> User.withUsername(user.getUsername())
				.password(user.getPasswordHash())
				.disabled(!user.isEnabled())
				.accountLocked(user.isAccountLocked())
				.accountExpired(user.isAccountExpired())
				.credentialsExpired(user.isCredentialsExpired())
				.authorities(user.getRoleCodes().stream()
					// 角色 code 全小写存储（admin / customer），Spring Security 侧统一加
					// ROLE_ 前缀并大写，使 hasRole("ADMIN") 与 hasAuthority("ROLE_ADMIN") 都成立。
					.map((code) -> (GrantedAuthority) new SimpleGrantedAuthority(
							"ROLE_" + code.toUpperCase(java.util.Locale.ROOT)))
					.toList())
				.build())
			.orElseThrow(() -> new UsernameNotFoundException("用户不存在或凭据无效"));
	}

}
