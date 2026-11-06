package com.mao.sso.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import com.mao.sso.exception.DuplicateResourceException;
import com.mao.sso.exception.ResourceNotFoundException;
import com.mao.sso.support.IntegrationTestSupport;

/**
 * 用户体系测试：创建、唯一约束、状态管理、角色模型。
 */
@SpringBootTest
@AutoConfigureMockMvc
class UserServiceTest extends IntegrationTestSupport {

	@Autowired
	private UserService userService;

	@Autowired
	private UserRepository userRepository;

	@Test
	@DisplayName("创建用户并分配角色")
	void createsUserWithRoles() {
		var user = userService.createUser("svc-alice", "svc-alice@mao.local", "Passw0rd!", "Alice",
				java.util.Set.of(UserService.ROLE_USER));
		assertThat(user.getId()).isNotNull();
		assertThat(user.getRoles()).extracting(Role::getCode).containsExactly(UserService.ROLE_USER);
		assertThat(user.isEnabled()).isTrue();
		assertThat(user.getPasswordHash()).isNotEqualTo("Passw0rd!");
		assertThat(user.getCreatedAt()).isNotNull();
		assertThat(user.getUpdatedAt()).isNotNull();
	}

	@Test
	@DisplayName("用户名重复时抛出业务异常")
	void rejectsDuplicateUsername() {
		userService.createUser("svc-bob", "svc-bob@mao.local", "Passw0rd!", "Bob",
				java.util.Set.of(UserService.ROLE_USER));
		assertThatThrownBy(() -> userService.createUser("svc-bob", "svc-bob2@mao.local", "Passw0rd!", "Bob2",
				java.util.Set.of(UserService.ROLE_USER)))
			.isInstanceOf(DuplicateResourceException.class)
			.hasMessageContaining("用户名已存在");
	}

	@Test
	@DisplayName("邮箱重复时抛出业务异常")
	void rejectsDuplicateEmail() {
		userService.createUser("svc-carol", "svc-carol@mao.local", "Passw0rd!", "Carol",
				java.util.Set.of(UserService.ROLE_USER));
		assertThatThrownBy(() -> userService.createUser("svc-carol2", "svc-carol@mao.local", "Passw0rd!", "Carol2",
				java.util.Set.of(UserService.ROLE_USER)))
			.isInstanceOf(DuplicateResourceException.class)
			.hasMessageContaining("邮箱已存在");
	}

	@Test
	@DisplayName("更新密码后旧密码失效")
	void updatesPassword() {
		var user = userService.createUser("svc-dave", "svc-dave@mao.local", "Passw0rd!", "Dave",
				java.util.Set.of(UserService.ROLE_USER));
		userService.updatePassword(user.getId(), "N3wPassw0rd!");
		var encoder = new org.springframework.security.crypto.argon2.Argon2PasswordEncoder(16, 32, 1, 19456, 2);
		var reloaded = userRepository.findById(user.getId()).orElseThrow();
		assertThat(encoder.matches("N3wPassw0rd!", reloaded.getPasswordHash())).isTrue();
		assertThat(encoder.matches("Passw0rd!", reloaded.getPasswordHash())).isFalse();
	}

	@Test
	@DisplayName("更新启用/锁定状态")
	void updatesStatus() {
		var user = userService.createUser("svc-erin", "svc-erin@mao.local", "Passw0rd!", "Erin",
				java.util.Set.of(UserService.ROLE_USER));
		userService.updateStatus(user.getId(), false, true);
		var reloaded = userRepository.findById(user.getId()).orElseThrow();
		assertThat(reloaded.isEnabled()).isFalse();
		assertThat(reloaded.isAccountLocked()).isTrue();
	}

	@Test
	@DisplayName("角色不存在时抛出业务异常")
	void rejectsUnknownRole() {
		assertThatThrownBy(() -> userService.createUser("svc-frank", "svc-frank@mao.local", "Passw0rd!", "Frank",
				java.util.Set.of("ROLE_NOT_EXIST")))
			.isInstanceOf(ResourceNotFoundException.class);
	}

	@Test
	@DisplayName("确保预置角色存在（幂等）")
	void ensuresBuiltInRolesIdempotently() {
		userService.ensureRole(UserService.ROLE_USER, "普通用户", "已认证的普通用户");
		userService.ensureRole(UserService.ROLE_USER, "普通用户", "已认证的普通用户");
		var role = userService.findRoleByCode(UserService.ROLE_USER);
		assertThat(role.getName()).isEqualTo("普通用户");
	}

}
