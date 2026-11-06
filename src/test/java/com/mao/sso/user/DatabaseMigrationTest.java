package com.mao.sso.user;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import com.mao.sso.support.IntegrationTestSupport;

/**
 * 数据库迁移测试：验证 Flyway 迁移完整应用、表结构齐全、可重复执行。
 */
@SpringBootTest
@AutoConfigureMockMvc
class DatabaseMigrationTest extends IntegrationTestSupport {

	private static final List<String> EXPECTED_TABLES = List.of("users", "roles", "user_roles",
			"oauth2_registered_client", "oauth2_authorization", "oauth2_authorization_consent");

	@Autowired
	private JdbcTemplate jdbcTemplate;

	@Autowired
	private org.flywaydb.core.Flyway flyway;

	@Test
	@DisplayName("Flyway 迁移全部成功应用")
	void allMigrationsApplied() {
		var applied = this.flyway.info().applied();
		assertThat(applied).isNotEmpty();
		assertThat(applied).hasSize(4);
		assertThat(this.flyway.info().pending()).isEmpty();
	}

	@Test
	@DisplayName("重复执行迁移不会产生新变更（幂等）")
	void migrateIsIdempotent() {
		int before = this.flyway.info().applied().length;
		var result = this.flyway.migrate();
		assertThat(result.migrationsExecuted).isZero();
		assertThat(this.flyway.info().applied()).hasSize(before);
	}

	@Test
	@DisplayName("用户表与 OAuth 官方表全部存在")
	void allTablesExist() {
		for (String table : EXPECTED_TABLES) {
			Integer count = this.jdbcTemplate.queryForObject(
					"SELECT COUNT(*) FROM information_schema.tables WHERE table_name = ? "
							+ "AND LOWER(table_schema) <> 'information_schema'",
					Integer.class, table);
			assertThat(count).as("表 %s 应存在", table).isEqualTo(1);
		}
	}

	@Test
	@DisplayName("预置角色已由迁移脚本插入")
	void builtInRolesSeeded() {
		Integer count = this.jdbcTemplate.queryForObject(
				"SELECT COUNT(*) FROM roles WHERE code IN ('ROLE_USER','ROLE_ADMIN')", Integer.class);
		assertThat(count).isEqualTo(2);
	}

	@Test
	@DisplayName("OAuth 客户端表包含 client_id 唯一索引")
	void registeredClientHasUniqueClientIdIndex() {
		// 逻辑唯一约束由 DDL 保证：重复 client_id 插入应失败
		assertThatThrownByInsertDuplicateClientId();
	}

	private void assertThatThrownByInsertDuplicateClientId() {
		this.jdbcTemplate.execute("INSERT INTO oauth2_registered_client (id, client_id, client_id_issued_at, "
				+ "client_secret, client_name, client_authentication_methods, authorization_grant_types, "
				+ "redirect_uris, scopes, client_settings, token_settings) VALUES "
				+ "('dup-id-1', 'dup-client', CURRENT_TIMESTAMP, 'secret', 'Dup', 'none', 'authorization_code', "
				+ "'http://localhost/cb', 'openid', '{}', '{}')");
		try {
			this.jdbcTemplate.execute("INSERT INTO oauth2_registered_client (id, client_id, client_id_issued_at, "
					+ "client_secret, client_name, client_authentication_methods, authorization_grant_types, "
					+ "redirect_uris, scopes, client_settings, token_settings) VALUES "
					+ "('dup-id-2', 'dup-client', CURRENT_TIMESTAMP, 'secret', 'Dup2', 'none', "
					+ "'authorization_code', 'http://localhost/cb', 'openid', '{}', '{}')");
			org.assertj.core.api.Assertions.fail("重复 client_id 应当插入失败");
		}
		catch (org.springframework.dao.DataIntegrityViolationException expected) {
			// 预期行为
		}
		finally {
			this.jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE id LIKE 'dup-id-%'");
		}
	}

}
