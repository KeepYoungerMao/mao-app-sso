package com.mao.sso.support;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.flywaydb.core.Flyway;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * 集成测试基类。
 *
 * <h3>数据库策略（已移除 H2 与 Testcontainers）</h3>
 * <p>直接连接本地 MySQL 测试库，默认
 * {@code jdbc:mysql://127.0.0.1:3306/mao_sso_test}，可通过环境变量覆盖：</p>
 * <ul>
 *   <li>{@code SSO_TEST_DATASOURCE_URL}</li>
 *   <li>{@code SSO_TEST_DATASOURCE_USERNAME}（默认 root）</li>
 *   <li>{@code SSO_TEST_DATASOURCE_PASSWORD}（默认 root）</li>
 * </ul>
 *
 * <p><b>安全护栏</b>：启动前会执行 Flyway {@code clean + migrate} 重置库结构，
 * 因此要求 URL 中的库名必须包含 {@code test}，防止误连开发/生产库造成数据丢失。</p>
 */
public abstract class IntegrationTestSupport {

	protected static final Logger log = LoggerFactory.getLogger(IntegrationTestSupport.class);

	private static final String DEFAULT_URL = "jdbc:mysql://127.0.0.1:3306/mao_sso_test"
			+ "?createDatabaseIfNotExist=true&preserveInstants=true&connectionTimeZone=UTC"
			+ "&forceConnectionTimeZoneToSession=true&allowPublicKeyRetrieval=true&sslMode=DISABLED";

	private static final String URL = env("SSO_TEST_DATASOURCE_URL", DEFAULT_URL);

	private static final String USERNAME = env("SSO_TEST_DATASOURCE_USERNAME", "root");

	private static final String PASSWORD = env("SSO_TEST_DATASOURCE_PASSWORD", "root");

	static {
		resetDatabase();
	}

	private static String env(String key, String defaultValue) {
		String value = System.getenv(key);
		return (value != null && !value.isBlank()) ? value : defaultValue;
	}

	/**
	 * 重置测试库：Flyway clean（清空所有对象）后重新执行迁移，保证测试从确定状态开始。
	 */
	private static void resetDatabase() {
		String lower = URL.toLowerCase();
		if (!lower.contains("test")) {
			throw new IllegalStateException(
					"拒绝在非测试库上执行 clean：SSO_TEST_DATASOURCE_URL=" + URL + "（库名必须包含 test）");
		}
		Flyway flyway = Flyway.configure()
			.dataSource(URL, USERNAME, PASSWORD)
			.locations("classpath:db/migration")
			.cleanDisabled(false)
			.load();
		flyway.clean();
		flyway.migrate();
		log.info("测试数据库已重置（clean + migrate）: {}", URL);
	}

	@DynamicPropertySource
	static void datasourceProperties(DynamicPropertyRegistry registry) {
		registry.add("spring.datasource.url", () -> URL);
		registry.add("spring.datasource.username", () -> USERNAME);
		registry.add("spring.datasource.password", () -> PASSWORD);
		registry.add("spring.datasource.driver-class-name", () -> "com.mysql.cj.jdbc.Driver");
		registry.add("spring.flyway.enabled", () -> "true");
		registry.add("spring.flyway.clean-disabled", () -> "false");
	}

	// ---------- PKCE 工具 ----------

	public record PkcePair(String codeVerifier, String codeChallenge) {
	}

	public static PkcePair generatePkce() {
		byte[] random = new byte[32];
		new java.security.SecureRandom().nextBytes(random);
		String codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
		String codeChallenge;
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			codeChallenge = Base64.getUrlEncoder().withoutPadding()
				.encodeToString(digest.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII)));
		}
		catch (NoSuchAlgorithmException ex) {
			throw new IllegalStateException(ex);
		}
		return new PkcePair(codeVerifier, codeChallenge);
	}

	/** 从 URL 查询串中提取参数值（已解码）。 */
	public static String queryParameter(String url, String name) {
		int queryStart = url.indexOf('?');
		if (queryStart < 0) {
			return null;
		}
		for (String pair : url.substring(queryStart + 1).split("&")) {
			int eq = pair.indexOf('=');
			if (eq > 0 && pair.substring(0, eq).equals(name)) {
				return java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
			}
		}
		return null;
	}

	/**
	 * 将请求参数镜像到查询串。
	 *
	 * <p>Spring Authorization Server 的 GET 端点通过 {@code request.getQueryString().contains(key)}
	 * 判定参数来源（OAuth2EndpointUtils#getQueryParameters），而 MockMvc 的 {@code .param()}
	 * 只写入参数 Map、不设置查询串。该后处理器用于让 MockMvc 下的 GET 请求被 SAS 正确识别。</p>
	 *
	 * <p>仅用于 GET 请求；POST 表单参数不应使用（SAS 的 getFormParameters 依赖查询串不含该键）。</p>
	 */
	public static org.springframework.test.web.servlet.request.RequestPostProcessor syncQueryString() {
		return (request) -> {
			String queryString = request.getParameterMap()
				.entrySet()
				.stream()
				.filter((entry) -> entry.getValue().length > 0)
				.map((entry) -> urlEncode(entry.getKey()) + "=" + urlEncode(entry.getValue()[0]))
				.collect(java.util.stream.Collectors.joining("&"));
			request.setQueryString(queryString.isEmpty() ? null : queryString);
			return request;
		};
	}

	private static String urlEncode(String value) {
		return java.net.URLEncoder.encode(value, StandardCharsets.UTF_8);
	}

}
