package com.mao.sso.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mao.sso.user.UserRepository;

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
 * <p>注意：认证失败信息不区分“用户不存在”与“密码错误”，
 * 由登录失败处理器统一返回通用提示，防止用户枚举。</p>
 */
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

	private final UserRepository userRepository;

	public UserDetailsServiceImpl(UserRepository userRepository) {
		this.userRepository = userRepository;
	}

	@Override
	@Transactional(readOnly = true)
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		String identifier = (username == null) ? "" : username.trim();
		return this.userRepository.findByIdentifierWithRoles(identifier)
			.map((user) -> User.withUsername(user.getUsername())
				.password(user.getPasswordHash())
				.disabled(!user.isEnabled())
				.accountLocked(user.isAccountLocked())
				.accountExpired(user.isAccountExpired())
				.credentialsExpired(user.isCredentialsExpired())
				.authorities(user.getRoles().stream()
					.map((role) -> (GrantedAuthority) new SimpleGrantedAuthority(role.getCode()))
					.toList())
				.build())
			.orElseThrow(() -> new UsernameNotFoundException("用户不存在或凭据无效"));
	}

}
