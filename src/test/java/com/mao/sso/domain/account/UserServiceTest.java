package com.mao.sso.domain.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.mao.sso.api.dto.CreatedUser;
import com.mao.sso.api.user.UserService;
import com.mao.sso.auth.bootstrap.UserInitializer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.mao.sso.domain.error.DuplicateResourceException;
import com.mao.sso.domain.error.ResourceNotFoundException;
import com.mao.sso.support.IntegrationTestSupport;
import com.mao.sso.domain.mapper.UserMapper;

/**
 * 用户体系测试：创建、唯一约束、状态管理、角色绑定、密码策略。
 */
@SpringBootTest
@AutoConfigureMockMvc
class UserServiceTest extends IntegrationTestSupport {

	@Autowired
	private UserService userService;

	@Autowired
	private UserMapper userMapper;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private UserInitializer userInitializer;

	/**
	 * 清掉本类自建的角色。
	 *
	 * <p>测试库是全类共享的，{@code ensuresBuiltInRolesIdempotently} 会插入
	 * {@code auditor}。如果不清理，
	 * 对「预置角色恰好是 admin / customer」的断言就会随测试类执行顺序随机失败。</p>
	 */
	@AfterEach
	void removeRolesCreatedByTests() {
		this.jdbcTemplate.update("DELETE FROM user_roles WHERE role_id IN "
				+ "(SELECT id FROM roles WHERE code NOT IN (?, ?))", UserService.ROLE_ADMIN, UserService.ROLE_CUSTOMER);
		this.jdbcTemplate.update("DELETE FROM roles WHERE code NOT IN (?, ?)", UserService.ROLE_ADMIN,
				UserService.ROLE_CUSTOMER);
	}

	@Test
	@DisplayName("创建用户并分配角色")
	void createsUserWithRoles() {
		var user = this.userService.createUser("svc-alice", "svc-alice@mao.local", "Passw0rd!", "Alice",
				java.util.Set.of(UserService.ROLE_CUSTOMER));
		assertThat(user.getId()).isNotNull();

		var reloaded = this.userMapper.findByIdWithRoles(user.getId()).orElseThrow();
		assertThat(reloaded.getRoleCodes()).containsExactly(UserService.ROLE_CUSTOMER);
		assertThat(reloaded.isEnabled()).isTrue();
		assertThat(reloaded.getPasswordHash()).isNotEqualTo("Passw0rd!");
		assertThat(reloaded.getCreatedAt()).isNotNull();
		assertThat(reloaded.getUpdatedAt()).isNotNull();
		assertThat(reloaded.getCreatedBy()).isNotBlank();
	}

	@Test
	@DisplayName("管理员创建用户时生成一次性密码并要求改密")
	void adminCreateReturnsOneTimePassword() {
		CreatedUser created = this.userService.createUserByAdmin("svc-onetime", "svc-onetime@mao.local",
				"一次性密码用户", "13800000000", null, java.util.Set.of(UserService.ROLE_CUSTOMER));

		assertThat(created.rawPassword()).hasSize(16);
		var reloaded = this.userMapper.findByIdWithRoles(created.id()).orElseThrow();
		assertThat(reloaded.isMustChangePassword()).isTrue();
		assertThat(reloaded.getCredentialsExpiredAt()).isNull();
		assertThat(reloaded.getPhone()).isEqualTo("13800000000");
		assertThat(this.passwordEncoder.matches(created.rawPassword(), reloaded.getPasswordHash())).isTrue();
	}

	@Test
	@DisplayName("用户名重复时抛出业务异常")
	void rejectsDuplicateUsername() {
		this.userService.createUser("svc-bob", "svc-bob@mao.local", "Passw0rd!", "Bob",
				java.util.Set.of(UserService.ROLE_CUSTOMER));
		assertThatThrownBy(() -> this.userService.createUser("svc-bob", "svc-bob2@mao.local", "Passw0rd!",
				"Bob2", java.util.Set.of(UserService.ROLE_CUSTOMER)))
			.isInstanceOf(DuplicateResourceException.class)
			.hasMessageContaining("用户名已存在");
	}

	@Test
	@DisplayName("邮箱重复时抛出业务异常")
	void rejectsDuplicateEmail() {
		this.userService.createUser("svc-carol", "svc-carol@mao.local", "Passw0rd!", "Carol",
				java.util.Set.of(UserService.ROLE_CUSTOMER));
		assertThatThrownBy(() -> this.userService.createUser("svc-carol2", "svc-carol@mao.local", "Passw0rd!",
				"Carol2", java.util.Set.of(UserService.ROLE_CUSTOMER)))
			.isInstanceOf(DuplicateResourceException.class)
			.hasMessageContaining("邮箱已存在");
	}

	@Test
	@DisplayName("更新密码后旧密码失效，并清除需改密标记")
	void updatesPassword() {
		var user = this.userService.createUser("svc-dave", "svc-dave@mao.local", "Passw0rd!", "Dave",
				java.util.Set.of(UserService.ROLE_CUSTOMER));
		this.userService.changePassword(user.getId(), "N3wPassw0rd!");

		var reloaded = this.userMapper.findById(user.getId()).orElseThrow();
		assertThat(this.passwordEncoder.matches("N3wPassw0rd!", reloaded.getPasswordHash())).isTrue();
		assertThat(this.passwordEncoder.matches("Passw0rd!", reloaded.getPasswordHash())).isFalse();
		assertThat(reloaded.isMustChangePassword()).isFalse();
	}

	@Test
	@DisplayName("重置密码返回一次性新密码并置需改密标记")
	void resetsPasswordWithOneTimeValue() {
		var user = this.userService.createUser("svc-reset", "svc-reset@mao.local", "Passw0rd!", "Reset",
				java.util.Set.of(UserService.ROLE_CUSTOMER));

		String newPassword = this.userService.resetPassword(user.getId());
		assertThat(newPassword).hasSize(16);

		var reloaded = this.userMapper.findById(user.getId()).orElseThrow();
		assertThat(reloaded.isMustChangePassword()).isTrue();
		assertThat(this.passwordEncoder.matches(newPassword, reloaded.getPasswordHash())).isTrue();
	}

	@Test
	@DisplayName("更新启用/锁定状态")
	void updatesStatus() {
		var user = this.userService.createUser("svc-erin", "svc-erin@mao.local", "Passw0rd!", "Erin",
				java.util.Set.of(UserService.ROLE_CUSTOMER));
		this.userService.updateStatus(user.getId(), false, true);

		var reloaded = this.userMapper.findById(user.getId()).orElseThrow();
		assertThat(reloaded.isEnabled()).isFalse();
		assertThat(reloaded.isAccountLocked()).isTrue();
	}

	@Test
	@DisplayName("角色绑定为全量替换")
	void rebindsRoles() {
		var user = this.userService.createUser("svc-grace", "svc-grace@mao.local", "Passw0rd!", "Grace",
				java.util.Set.of(UserService.ROLE_CUSTOMER));

		this.userService.bindRoles(user.getId(), java.util.Set.of(UserService.ROLE_ADMIN));

		var reloaded = this.userMapper.findByIdWithRoles(user.getId()).orElseThrow();
		assertThat(reloaded.getRoleCodes()).containsExactly(UserService.ROLE_ADMIN);
	}

	@Test
	@DisplayName("密码续期写入到期时间，传空表示永不过期")
	void renewCredentialsExpiry() {
		var user = this.userService.createUser("svc-renee", "svc-renee@mao.local", "Passw0rd!", "Renee",
				java.util.Set.of(UserService.ROLE_CUSTOMER));

		java.time.Instant expiry = java.time.Instant.now().plus(java.time.Duration.ofDays(90));
		this.userService.renewCredentials(user.getId(), expiry);
		assertThat(this.userMapper.findById(user.getId()).orElseThrow().getCredentialsExpiredAt())
			.isNotNull();

		this.userService.renewCredentials(user.getId(), null);
		assertThat(this.userMapper.findById(user.getId()).orElseThrow().getCredentialsExpiredAt()).isNull();
	}

	@Test
	@DisplayName("角色不存在时抛出业务异常")
	void rejectsUnknownRole() {
		assertThatThrownBy(() -> this.userService.createUser("svc-frank", "svc-frank@mao.local", "Passw0rd!",
				"Frank", java.util.Set.of("ROLE_NOT_EXIST")))
			.isInstanceOf(ResourceNotFoundException.class);
	}

	@Test
	@DisplayName("确保角色存在（幂等，且不覆盖已存在角色的名称）")
	void ensuresBuiltInRolesIdempotently() {
		// 迁移已预置 admin / customer，先确认它们在
		assertThat(this.userService.findRoleByCode(UserService.ROLE_ADMIN)).isNotNull();
		assertThat(this.userService.findRoleByCode(UserService.ROLE_CUSTOMER)).isNotNull();

		// 重复 ensureRole 只创建一次
		this.userInitializer.ensureRole("auditor", "审计员", "只读审计");
		this.userInitializer.ensureRole("auditor", "审计员", "只读审计");
		assertThat(this.userService.findRoleByCode("auditor").getName()).isEqualTo("审计员");
		assertThat(this.userService.findAllRoles().stream().filter((r) -> r.getCode().equals("auditor")).count())
			.isEqualTo(1);
	}

	@Test
	@DisplayName("物理删除用户后不可再查到")
	void deletesUserPhysically() {
		var user = this.userService.createUser("svc-heidi", "svc-heidi@mao.local", "Passw0rd!", "Heidi",
				java.util.Set.of(UserService.ROLE_CUSTOMER));
		this.userService.deleteUser(user.getId());
		assertThat(this.userMapper.findById(user.getId())).isEmpty();
	}

}
