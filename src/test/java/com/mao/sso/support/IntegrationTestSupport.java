package com.mao.sso.support;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testcontainers.containers.MySQLContainer;

import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/**
 * 集成测试基类。
 *
 * <h3>数据库策略</h3>
 * <ul>
 *   <li>优先使用 Testcontainers MySQL（与生产数据库完全一致）；</li>
 *   <li>当前环境无 Docker 时自动回退到 H2（MySQL 兼容模式），
 *       保证同样的集成测试可在任意环境执行；回退时打印 WARN 日志。</li>
 * </ul>
 *
 * <p>所有测试共享同一个 Spring 上下文与数据库（容器/内存库仅启动一次）。</p>
 */
public abstract class IntegrationTestSupport {

	protected static final Logger log = LoggerFactory.getLogger(IntegrationTestSupport.class);

	private static MySQLContainer<?> mysqlContainer;

	static {
		if (isDockerAvailable()) {
			mysqlContainer = new MySQLContainer<>("mysql:8.0");
			mysqlContainer.start();
			log.info("Testcontainers MySQL 已启动: {}", mysqlContainer.getJdbcUrl());
		}
		else {
			log.warn("================================================================");
			log.warn("未检测到 Docker 环境，集成测试回退到 H2（MySQL 兼容模式）。");
			log.warn("生产与 CI（有 Docker）环境仍使用 Testcontainers MySQL，行为一致。");
			log.warn("================================================================");
		}
	}

	protected static boolean isMySql() {
		return mysqlContainer != null;
	}

	@DynamicPropertySource
	static void datasourceProperties(DynamicPropertyRegistry registry) {
		if (mysqlContainer != null) {
			// 追加 Instant 存取参数（Spring Authorization Server 官方 schema 对 MySQL 的要求）
			String url = mysqlContainer.getJdbcUrl()
					+ "&preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true";
			registry.add("spring.datasource.url", () -> url);
			registry.add("spring.datasource.username", mysqlContainer::getUsername);
			registry.add("spring.datasource.password", mysqlContainer::getPassword);
			registry.add("spring.datasource.driver-class-name", () -> "com.mysql.cj.jdbc.Driver");
		}
		else {
			registry.add("spring.datasource.url",
					() -> "jdbc:h2:mem:maosso;MODE=MySQL;DB_CLOSE_DELAY=-1;DATABASE_TO_LOWER=TRUE");
			registry.add("spring.datasource.username", () -> "sa");
			registry.add("spring.datasource.password", () -> "");
			registry.add("spring.datasource.driver-class-name", () -> "org.h2.Driver");
		}
	}

	private static boolean isDockerAvailable() {
		try {
			return org.testcontainers.DockerClientFactory.instance().isDockerAvailable();
		}
		catch (Throwable ex) {
			return false;
		}
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
