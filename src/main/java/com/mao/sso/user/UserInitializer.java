package com.mao.sso.user;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.mao.sso.config.SsoProperties;

/**
 * 启动初始化：预置角色 + 开发管理员账号。
 *
 * <h3>安全约束</h3>
 * <ul>
 *   <li>管理员密码只从环境变量 {@code SSO_ADMIN_PASSWORD} 读取，代码中没有任何默认密码；</li>
 *   <li>未配置密码时跳过初始化并打印 WARN（生产环境同样禁止固定默认密码）；</li>
 *   <li>整个流程幂等：重复启动不会重复创建用户或角色。</li>
 * </ul>
 */
@Component
public class UserInitializer {

	private static final Logger log = LoggerFactory.getLogger(UserInitializer.class);

	private final UserService userService;

	private final UserRepository userRepository;

	private final SsoProperties properties;

	public UserInitializer(UserService userService, UserRepository userRepository, SsoProperties properties) {
		this.userService = userService;
		this.userRepository = userRepository;
		this.properties = properties;
	}

	@EventListener(ApplicationReadyEvent.class)
	@Order(10)
	@Transactional
	public void initialize() {
		ensureBuiltInRoles();
		ensureAdminUser();
	}

	private void ensureBuiltInRoles() {
		this.userService.ensureRole(UserService.ROLE_USER, "普通用户", "已认证的普通用户");
		this.userService.ensureRole(UserService.ROLE_ADMIN, "管理员", "系统管理员，拥有全部权限");
	}

	private void ensureAdminUser() {
		String username = this.properties.getAdmin().getUsername();
		String rawPassword = this.properties.getAdmin().getPassword();
		if (!StringUtils.hasText(rawPassword)) {
			log.warn("未配置环境变量 SSO_ADMIN_PASSWORD，跳过初始管理员创建（幂等保护：已存在则不受影响）");
			return;
		}
		if (this.userRepository.existsByUsername(username)) {
			log.info("初始管理员已存在，跳过创建: username={}", username);
			return;
		}
		this.userService.createUser(username, this.properties.getAdmin().getEmail(), rawPassword,
				this.properties.getAdmin().getDisplayName(), java.util.Set.of(UserService.ROLE_ADMIN,
						UserService.ROLE_USER));
		log.info("已创建初始管理员: username={}", username);
	}

}
