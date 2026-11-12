package com.mao.sso.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;

import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.mao.sso.common.page.PageQuery;
import com.mao.sso.common.page.PageResult;
import com.mao.sso.exception.DuplicateResourceException;
import com.mao.sso.exception.InvalidRequestException;
import com.mao.sso.support.IntegrationTestSupport;

/**
 * 客户端注册服务测试。
 *
 * <p>核心验证项目约定：<b>一个客户端只允许配置一个 redirect_uri</b>。
 * 覆盖创建、更新（替换而非追加）、空白值、以及「逗号」这个存储层陷阱。</p>
 */
@SpringBootTest
class ClientServiceTest extends IntegrationTestSupport {

	@Autowired
	private ClientService clientService;

	@Autowired
	private RegisteredClientRepository repository;

	@Test
	@DisplayName("创建客户端后只保存一条回调地址")
	void createStoresExactlyOneRedirectUri() {
		String clientId = uniqueId("cs-one");
		String redirectUri = "https://" + clientId + ".example.com/callback";

		this.clientService.createClient(clientId, "单回调客户端", null, List.of("none"),
				List.of("authorization_code"), redirectUri, List.of("openid"), false, true);

		RegisteredClient saved = this.repository.findByClientId(clientId);
		assertThat(saved).isNotNull();
		assertThat(saved.getRedirectUris()).containsExactly(redirectUri);
	}

	@Test
	@DisplayName("创建时不提供回调地址直接拒绝")
	void createRejectsMissingRedirectUri() {
		assertThatThrownBy(() -> this.clientService.createClient(uniqueId("cs-empty"), "空回调", null,
				List.of("none"), List.of("authorization_code"), "   ", List.of("openid"), false, true))
			.isInstanceOf(InvalidRequestException.class)
			.hasMessageContaining("必须配置一个 redirect_uri");
	}

	@Test
	@DisplayName("回调地址含逗号被拒绝（注册表以逗号分隔存储，否则会被拆成两个回调）")
	void createRejectsRedirectUriWithComma() {
		assertThatThrownBy(() -> this.clientService.createClient(uniqueId("cs-comma"), "逗号回调", null,
				List.of("none"), List.of("authorization_code"), "https://a.example.com/cb?x=1,2",
				List.of("openid"), false, true))
			.isInstanceOf(InvalidRequestException.class)
			.hasMessageContaining("逗号");
	}

	@Test
	@DisplayName("回调地址含通配符被拒绝")
	void createRejectsWildcardRedirectUri() {
		assertThatThrownBy(() -> this.clientService.createClient(uniqueId("cs-star"), "通配回调", null,
				List.of("none"), List.of("authorization_code"), "https://*.example.com/callback",
				List.of("openid"), false, true))
			.isInstanceOf(InvalidRequestException.class)
			.hasMessageContaining("通配符");
	}

	@Test
	@DisplayName("回调地址必须是绝对 URI")
	void createRejectsRelativeRedirectUri() {
		assertThatThrownBy(() -> this.clientService.createClient(uniqueId("cs-rel"), "相对回调", null,
				List.of("none"), List.of("authorization_code"), "/callback", List.of("openid"), false, true))
			.isInstanceOf(InvalidRequestException.class)
			.hasMessageContaining("绝对 URI");
	}

	@Test
	@DisplayName("更新回调地址是替换而非追加，客户端始终只有一条")
	void updateReplacesInsteadOfAppending() {
		String clientId = uniqueId("cs-update");
		String original = "https://" + clientId + ".example.com/original";
		String replaced = "https://" + clientId + ".example.com/replaced";

		this.clientService.createClient(clientId, "更新客户端", null, List.of("none"),
				List.of("authorization_code"), original, List.of("openid"), false, true);

		this.clientService.updateClient(clientId, null, replaced, null, null, null);

		// 关键断言：若误用 Builder.redirectUri(String) 的追加语义，这里会变成 2 条
		assertThat(this.repository.findByClientId(clientId).getRedirectUris()).containsExactly(replaced);
	}

	@Test
	@DisplayName("更新时回调地址留空表示保持不变")
	void updateWithBlankRedirectKeepsExisting() {
		String clientId = uniqueId("cs-keep");
		String original = "https://" + clientId + ".example.com/callback";

		this.clientService.createClient(clientId, "保持回调", null, List.of("none"),
				List.of("authorization_code"), original, List.of("openid"), false, true);

		this.clientService.updateClient(clientId, "改名后的客户端", null, null, null, null);

		RegisteredClient updated = this.repository.findByClientId(clientId);
		assertThat(updated.getClientName()).isEqualTo("改名后的客户端");
		assertThat(updated.getRedirectUris()).containsExactly(original);
	}

	@Test
	@DisplayName("创建时回调地址已被其它客户端占用则拒绝")
	void createRejectsRedirectUriOwnedByAnotherClient() {
		String owner = uniqueId("cs-owner");
		String redirectUri = "https://" + owner + ".example.com/callback";
		createPublic(this.clientService, owner, redirectUri);

		assertThatThrownBy(() -> createPublic(this.clientService, uniqueId("cs-thief"), redirectUri))
			.isInstanceOf(DuplicateResourceException.class)
			.hasMessageContaining(owner);
	}

	@Test
	@DisplayName("更新时不能抢占其它客户端的回调地址，且原值不受影响")
	void updateRejectsRedirectUriOwnedByAnotherClient() {
		String owner = uniqueId("cs-hold");
		String ownerUri = "https://" + owner + ".example.com/callback";
		createPublic(this.clientService, owner, ownerUri);

		String other = uniqueId("cs-other");
		String otherUri = "https://" + other + ".example.com/callback";
		createPublic(this.clientService, other, otherUri);

		assertThatThrownBy(() -> this.clientService.updateClient(other, null, ownerUri, null, null, null))
			.isInstanceOf(DuplicateResourceException.class)
			.hasMessageContaining(owner);

		assertThat(this.repository.findByClientId(other).getRedirectUris()).containsExactly(otherUri);
	}

	@Test
	@DisplayName("更新时保持自己的回调地址不视为冲突")
	void updateKeepsOwnRedirectUriWithoutConflict() {
		String clientId = uniqueId("cs-self");
		String redirectUri = "https://" + clientId + ".example.com/callback";
		createPublic(this.clientService, clientId, redirectUri);

		this.clientService.updateClient(clientId, "只改名", redirectUri, null, null, null);

		RegisteredClient updated = this.repository.findByClientId(clientId);
		assertThat(updated.getClientName()).isEqualTo("只改名");
		assertThat(updated.getRedirectUris()).containsExactly(redirectUri);
	}

	@Test
	@DisplayName("按回调地址可精确反查到客户端")
	void findByExactRedirectUriMatchesClient() {
		String clientId = uniqueId("cs-lookup");
		String redirectUri = "https://" + clientId + ".example.com/callback";

		this.clientService.createClient(clientId, "反查客户端", null, List.of("none"),
				List.of("authorization_code"), redirectUri, List.of("openid"), false, true);

		RegisteredClient found = this.clientService.findByExactRedirectUri(redirectUri);
		assertThat(found).isNotNull();
		assertThat(found.getClientId()).isEqualTo(clientId);
		assertThat(this.clientService.findByExactRedirectUri(redirectUri + "/nope")).isNull();
	}

	@Test
	@DisplayName("分页：一次取回整页并带审计字段，关键词过滤与总数正确")
	void pageClientsReturnsWholePageWithAudit() {
		String prefix = uniqueId("cs-page");
		for (int i = 0; i < 3; i++) {
			String clientId = prefix + "-" + i;
			createPublic(this.clientService, clientId, "https://" + clientId + ".example.com/cb");
		}

		PageQuery query = new PageQuery();
		query.setPageSize(2);

		PageResult<ClientService.ClientDetail> first = this.clientService.pageClients(query, prefix);
		assertThat(first.getTotal()).isEqualTo(3);
		assertThat(first.getRecords()).hasSize(2);
		// 审计字段随整页一起取回，说明没有逐条回查
		assertThat(first.getRecords()).allSatisfy((row) -> {
			assertThat(row.client().getClientId()).startsWith(prefix);
			assertThat(row.createdBy()).isNotBlank();
			assertThat(row.createdAt()).isNotNull();
			assertThat(row.updatedBy()).isNotBlank();
			assertThat(row.updatedAt()).isNotNull();
		});

		query.setPageNum(2);
		assertThat(this.clientService.pageClients(query, prefix).getRecords()).hasSize(1);
	}

	@Test
	@DisplayName("翻页不重不漏：签发时间同秒并列时按主键兜底，次序稳定")
	void pageClientsIsStableWhenIssuedAtTies() {
		String prefix = uniqueId("cs-tie");
		List<String> expected = new ArrayList<>();
		for (int i = 0; i < 5; i++) {
			String clientId = prefix + "-" + i;
			createPublic(this.clientService, clientId, "https://" + clientId + ".example.com/cb");
			expected.add(clientId);
		}

		List<String> collected = new ArrayList<>();
		for (int pageNum = 1; pageNum <= 3; pageNum++) {
			PageQuery query = new PageQuery();
			query.setPageNum(pageNum);
			query.setPageSize(2);
			this.clientService.pageClients(query, prefix)
				.getRecords()
				.forEach((row) -> collected.add(row.client().getClientId()));
		}

		assertThat(collected).doesNotHaveDuplicates().containsExactlyInAnyOrderElementsOf(expected);
	}

	@Test
	@DisplayName("分页只发两条 SQL（count + 整页），与页大小无关：N+1 已消除")
	void pageClientsIssuesTwoQueriesRegardlessOfPageSize() {
		String prefix = uniqueId("cs-sql");
		for (int i = 0; i < 5; i++) {
			String clientId = prefix + "-" + i;
			createPublic(this.clientService, clientId, "https://" + clientId + ".example.com/cb");
		}

		ch.qos.logback.classic.Logger jdbcLogger = (ch.qos.logback.classic.Logger) LoggerFactory
			.getLogger("org.springframework.jdbc.core.JdbcTemplate");
		ch.qos.logback.classic.Level previousLevel = jdbcLogger.getLevel();
		ListAppender<ILoggingEvent> appender = new ListAppender<>();
		appender.start();
		jdbcLogger.addAppender(appender);
		jdbcLogger.setLevel(ch.qos.logback.classic.Level.DEBUG);
		try {
			PageQuery query = new PageQuery();
			query.setPageSize(5);
			assertThat(this.clientService.pageClients(query, prefix).getRecords()).hasSize(5);
		}
		finally {
			jdbcLogger.setLevel(previousLevel);
			jdbcLogger.detachAppender(appender);
		}

		long statements = appender.list.stream()
			.map(ILoggingEvent::getFormattedMessage)
			.filter((message) -> message.startsWith("Executing prepared SQL statement"))
			.count();
		// 旧实现：1 次 count + 1 次取 id + 每行 1 次 findByClientId（控制器再各回查 2 次）
		assertThat(statements).isEqualTo(2);
	}

	/** 创建一个公共客户端（none + 强制 PKCE），用于回调地址冲突相关用例。 */
	private static void createPublic(ClientService clientService, String clientId, String redirectUri) {
		clientService.createClient(clientId, "客户端 " + clientId, null, List.of("none"),
				List.of("authorization_code"), redirectUri, List.of("openid"), false, true);
	}

	private static String uniqueId(String prefix) {
		return prefix + "-" + UUID.randomUUID().toString().substring(0, 8);
	}

}
