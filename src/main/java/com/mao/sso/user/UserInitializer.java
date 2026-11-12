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
 * 启动初始化：兜底角色、按需覆盖管理员密码。
 *
 * <p>角色（admin / customer）与默认管理员（admin）都由 Flyway 迁移 V2 预置，
 * 这里只做两件事：</p>
 * <ol>
 *   <li><b>幂等兜底</b>：确保两个内置角色存在（迁移被清理或误删后可自愈）；</li>
 *   <li><b>密码覆盖</b>：配置了 {@code SSO_ADMIN_PASSWORD} 时，用它覆盖迁移预置的默认密码
 *       （一次性：覆盖后会清除「必须改密」标记，后续启动不再改动）。</li>
 * </ol>
 *
 * <h3>默认凭据（务必先看这里）</h3>
 * <p>V2 迁移创建的管理员是 {@code admin} / {@code Admin@123456}，并置
 * {@code must_change_password = true}——登录后会被引导立即改密。
 * 生产环境请用 {@code SSO_ADMIN_PASSWORD} 覆盖，不要保留默认密码。</p>
 */
@Component
public class UserInitializer {

	private static final Logger log = LoggerFactory.getLogger(UserInitializer.class);

	private final UserService userService;

	private final SsoProperties properties;

	public UserInitializer(UserService userService, SsoProperties properties) {
		this.userService = userService;
		this.properties = properties;
	}

	@EventListener(ApplicationReadyEvent.class)
	@Order(10)
	@Transactional
	public void initialize() {
		ensureBuiltInRoles();
		applyAdminPassword();
	}

	private void ensureBuiltInRoles() {
		this.userService.ensureRole(UserService.ROLE_ADMIN, "管理员", "系统管理员，可访问管理 API");
		this.userService.ensureRole(UserService.ROLE_CUSTOMER, "客户", "普通业务用户，仅可登录与自助维护资料");
	}

	private void applyAdminPassword() {
		String username = this.properties.getAdmin().getUsername();
		String rawPassword = this.properties.getAdmin().getPassword();
		if (!StringUtils.hasText(rawPassword)) {
			if (this.userService.existsByUsername(username)) {
				log.warn("未配置 SSO_ADMIN_PASSWORD：管理员 {} 仍使用迁移预置的默认密码，"
						+ "首次登录会被要求改密（生产环境请务必覆盖）", username);
			}
			else {
				log.warn("未配置 SSO_ADMIN_PASSWORD 且管理员 {} 不存在，请手工创建或配置该变量", username);
			}
			return;
		}
		if (!this.userService.existsByUsername(username)) {
			this.userService.createUser(username, this.properties.getAdmin().getEmail(), rawPassword,
					this.properties.getAdmin().getDisplayName(), java.util.Set.of(UserService.ROLE_ADMIN));
			log.info("已创建初始管理员: username={}", username);
			return;
		}
		User existing = this.userService.requireUser(username);
		if (!existing.isMustChangePassword()) {
			log.info("管理员 {} 的密码已被设置过，跳过 SSO_ADMIN_PASSWORD 覆盖", username);
			return;
		}
		// 迁移预置的密码尚未被使用过：用环境变量覆盖，并清除「必须改密」标记
		this.userService.changePassword(existing.getId(), rawPassword);
		log.info("已用 SSO_ADMIN_PASSWORD 覆盖管理员 {} 的预置密码", username);
	}

}
