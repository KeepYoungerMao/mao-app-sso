package com.mao.sso.user;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import com.mao.sso.support.IntegrationTestSupport;

/**
 * 初始化幂等性测试：重复执行初始化不会重复创建用户/角色。
 */
@SpringBootTest
@AutoConfigureMockMvc
class UserInitializationTest extends IntegrationTestSupport {

	@Autowired
	private UserInitializer userInitializer;

	@Autowired
	private UserRepository userRepository;

	@Autowired
	private RoleRepository roleRepository;

	@Test
	@DisplayName("初始化逻辑可重复执行且结果幂等")
	void initializationIsIdempotent() {
		this.userInitializer.initialize();
		long usersAfterFirst = this.userRepository.count();
		long rolesAfterFirst = this.roleRepository.count();

		this.userInitializer.initialize();
		this.userInitializer.initialize();

		assertThat(this.userRepository.count()).isEqualTo(usersAfterFirst);
		assertThat(this.roleRepository.count()).isEqualTo(rolesAfterFirst);
	}

	@Test
	@DisplayName("预置角色始终存在")
	void builtInRolesAlwaysPresent() {
		this.userInitializer.initialize();
		assertThat(this.roleRepository.findByCode(UserService.ROLE_USER)).isPresent();
		assertThat(this.roleRepository.findByCode(UserService.ROLE_ADMIN)).isPresent();
	}

	@Test
	@DisplayName("未配置管理员密码时不创建管理员（无默认密码）")
	void noAdminCreatedWithoutPassword() {
		this.userInitializer.initialize();
		// 测试环境未提供 SSO_ADMIN_PASSWORD，admin 用户不应被创建
		assertThat(this.userRepository.findByUsername("admin")).isEmpty();
	}

}
