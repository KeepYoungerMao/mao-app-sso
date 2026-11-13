package com.mao.sso.auth.bootstrap;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;

import com.mao.sso.support.IntegrationTestSupport;
import com.mao.sso.api.user.UserService;
import com.mao.sso.domain.mapper.RoleMapper;
import com.mao.sso.domain.mapper.UserMapper;

/**
 * 初始化幂等性测试：重复执行初始化不会重复创建用户/角色。
 */
@SpringBootTest
@AutoConfigureMockMvc
class UserInitializationTest extends IntegrationTestSupport {

	@Autowired
	private UserInitializer userInitializer;

	@Autowired
	private UserMapper userMapper;

	@Autowired
	private RoleMapper roleMapper;

	@Test
	@DisplayName("初始化逻辑可重复执行且结果幂等")
	void initializationIsIdempotent() {
		this.userInitializer.initialize();
		long usersAfterFirst = this.userMapper.count();
		long rolesAfterFirst = this.roleMapper.count();

		this.userInitializer.initialize();
		this.userInitializer.initialize();

		assertThat(this.userMapper.count()).isEqualTo(usersAfterFirst);
		assertThat(this.roleMapper.count()).isEqualTo(rolesAfterFirst);
	}

	@Test
	@DisplayName("预置角色始终存在")
	void builtInRolesAlwaysPresent() {
		this.userInitializer.initialize();
		assertThat(this.roleMapper.findByCode(UserService.ROLE_CUSTOMER)).isPresent();
		assertThat(this.roleMapper.findByCode(UserService.ROLE_ADMIN)).isPresent();
	}

	@Test
	@DisplayName("未配置 SSO_ADMIN_PASSWORD 时不改动迁移预置的管理员密码")
	void seededAdminPasswordUntouchedWithoutEnv() {
		this.userInitializer.initialize();
		// 测试环境未提供 SSO_ADMIN_PASSWORD：迁移预置的 admin 应保持「首次登录需改密」
		assertThat(this.userMapper.findByUsername("admin")).isPresent()
			.get()
			.satisfies((admin) -> assertThat(admin.isMustChangePassword()).isTrue());
	}

}
