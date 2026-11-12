package com.mao.sso.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

import com.mao.sso.support.IntegrationTestSupport;

/**
 * 数据库迁移测试。
 *
 * <p>迁移只有两个版本：V1 客户端/授权相关表 + 默认管理客户端，
 * V2 用户/角色表 + 默认角色与默认管理员。本类验证结构、主键类型、审计字段、
 * 预置数据与唯一约束。</p>
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
	@DisplayName("Flyway 迁移全部成功应用（仅 V1、V2 两个版本）")
	void allMigrationsApplied() {
		var applied = this.flyway.info().applied();
		assertThat(applied).hasSize(2);
		assertThat(applied[0].getVersion().getVersion()).isEqualTo("1");
		assertThat(applied[1].getVersion().getVersion()).isEqualTo("2");
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
					"SELECT COUNT(*) FROM information_schema.tables "
							+ "WHERE table_schema = DATABASE() AND table_name = ?",
					Integer.class, table);
			assertThat(count).as("表 %s 应存在", table).isEqualTo(1);
		}
	}

	@Test
	@DisplayName("users 表字段齐全（含 phone/avatar/审计/密码过期时间），已废弃的布尔列不存在")
	void usersTableHasExpectedColumns() {
		List<String> columns = this.jdbcTemplate.queryForList(
				"SELECT column_name FROM information_schema.columns "
						+ "WHERE table_schema = DATABASE() AND table_name = 'users'",
				String.class);

		assertThat(columns).contains("phone", "avatar", "last_login_at", "must_change_password",
				"credentials_expired_at", "created_by", "updated_by");
		// 密码过期由 credentials_expired_at 单一来源表达
		assertThat(columns).doesNotContain("credentials_expired");
	}

	@Test
	@DisplayName("用户与角色主键为 INT")
	void primaryKeysAreInt() {
		assertThat(columnType("users", "id")).isEqualTo("int");
		assertThat(columnType("roles", "id")).isEqualTo("int");
		assertThat(columnType("user_roles", "user_id")).isEqualTo("int");
		assertThat(columnType("user_roles", "role_id")).isEqualTo("int");
	}

	@Test
	@DisplayName("客户端表包含审计字段")
	void registeredClientHasAuditColumns() {
		List<String> columns = this.jdbcTemplate.queryForList(
				"SELECT column_name FROM information_schema.columns "
						+ "WHERE table_schema = DATABASE() AND table_name = 'oauth2_registered_client'",
				String.class);
		assertThat(columns).contains("created_by", "created_at", "updated_by", "updated_at");
	}

	@Test
	@DisplayName("V2 预置角色：admin / customer")
	void builtInRolesSeeded() {
		List<String> codes = this.jdbcTemplate.queryForList("SELECT code FROM roles ORDER BY id", String.class);
		assertThat(codes).containsExactly("admin", "customer");
	}

	@Test
	@DisplayName("V2 预置管理员：admin 用户绑定 admin 角色，且标记为首次登录需改密")
	void defaultAdminSeeded() {
		Map<String, Object> admin = this.jdbcTemplate.queryForMap(
				"SELECT id, password_hash, must_change_password, enabled FROM users WHERE username = 'admin'");
		assertThat((String) admin.get("password_hash")).startsWith("$argon2id$");
		assertThat(admin.get("must_change_password")).isEqualTo(true);
		assertThat(admin.get("enabled")).isEqualTo(true);

		Integer bound = this.jdbcTemplate.queryForObject(
				"SELECT COUNT(*) FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
						+ "WHERE ur.user_id = ? AND r.code = 'admin'",
				Integer.class, admin.get("id"));
		assertThat(bound).isEqualTo(1);
	}

	@Test
	@DisplayName("V1 预置管理客户端：mao-app-admin，public client + PKCE，仅 openid/profile")
	void defaultAdminClientSeeded() {
		Map<String, Object> client = this.jdbcTemplate.queryForMap(
				"SELECT client_secret, client_authentication_methods, scopes, client_settings "
						+ "FROM oauth2_registered_client WHERE client_id = 'mao-app-admin'");
		assertThat(client.get("client_secret")).isNull();
		assertThat((String) client.get("client_authentication_methods")).contains("none");
		assertThat((String) client.get("scopes")).contains("openid").contains("profile").doesNotContain("email");
		assertThat((String) client.get("client_settings")).contains("settings.client.require-proof-key");
	}

	@Test
	@DisplayName("OAuth 客户端表包含 client_id 唯一索引")
	void registeredClientHasUniqueClientIdIndex() {
		assertThatThrownByInsertDuplicateClientId();
	}

	private String columnType(String table, String column) {
		return this.jdbcTemplate.queryForObject(
				"SELECT data_type FROM information_schema.columns "
						+ "WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?",
				String.class, table, column);
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
			fail("重复 client_id 应当插入失败");
		}
		catch (DataIntegrityViolationException expected) {
			// 预期行为
		}
		finally {
			this.jdbcTemplate.update("DELETE FROM oauth2_registered_client WHERE id LIKE 'dup-id-%'");
		}
	}

}
