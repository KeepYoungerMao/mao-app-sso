package com.mao.sso.oauth;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.StringUtils;

/**
 * 在 SAS 官方 JDBC 实现上补齐「分页」与「按回调地址反查」两类查询。
 *
 * <h2>为什么是继承，而不是自己写 SQL</h2>
 *
 * <p>{@link RegisteredClient} 的行映射不是简单取值：{@code client_authentication_methods} /
 * {@code authorization_grant_types} / {@code redirect_uris} / {@code post_logout_redirect_uris} /
 * {@code scopes} 是逗号分隔字符串（官方用 {@code StringUtils.commaDelimitedListToSet} 解析），
 * {@code client_settings} / {@code token_settings} 是 JSON（官方按自己的 ObjectMapper 配置反序列化，
 * 库里带着 {@code "@class"} 类型信息）。自己重写一遍等于复制官方内部实现，SAS 升级时会静默漂移。</p>
 *
 * <p>官方类把 {@code getJdbcOperations()} 与 {@code getRegisteredClientRowMapper()} 暴露为
 * {@code protected final}（且类非 final，setter 为 public final），正是给这种扩展留的缝——
 * 本类只负责「拼 SQL + 加审计列」，行映射全部委托给官方。</p>
 *
 * <h2>为什么 SELECT *</h2>
 *
 * <p>官方的列清单常量 {@code COLUMN_NAMES} 是 private，取不到。这里刻意不用硬编码列清单：
 * 行映射器按列名取值，将来 SAS 新增一列时 {@code SELECT *} 仍然可用，
 * 而抄一份列清单反而会因为「Column not found」直接报错。本表没有大字段，多取几列没有开销。</p>
 *
 * <h2>排序必须带主键兜底</h2>
 *
 * <p>{@code client_id_issued_at} 的列类型是 {@code timestamp}（秒精度，见 V1 迁移），
 * 批量创建（含测试）极易落在同一秒。只按它排序时 MySQL 不保证并列行的相对顺序，
 * {@code LIMIT/OFFSET} 翻页会出现重复或漏行，因此统一追加 {@code id} 作为稳定次序键。</p>
 */
public class PagingRegisteredClientRepository extends JdbcRegisteredClientRepository {

	private static final String TABLE = "oauth2_registered_client";

	private static final String KEYWORD_WHERE = " WHERE (client_id LIKE ? OR client_name LIKE ?)";

	private static final String ORDER_BY = " ORDER BY client_id_issued_at DESC, id";

	private final RowMapper<ClientRow> clientRowMapper;

	public PagingRegisteredClientRepository(JdbcOperations jdbcOperations) {
		super(jdbcOperations);
		RowMapper<RegisteredClient> delegate = getRegisteredClientRowMapper();
		this.clientRowMapper = (rs, rowNum) -> new ClientRow(delegate.mapRow(rs, rowNum),
				rs.getString("created_by"), toInstant(rs, "created_at"),
				rs.getString("updated_by"), toInstant(rs, "updated_at"));
	}

	/** 关键词命中总数（{@code client_id} / {@code client_name} 模糊匹配，关键词为空则统计全表）。 */
	public long count(String keyword) {
		boolean filtered = StringUtils.hasText(keyword);
		String sql = "SELECT COUNT(*) FROM " + TABLE + (filtered ? KEYWORD_WHERE : "");
		Long total = filtered
				? getJdbcOperations().queryForObject(sql, Long.class, like(keyword), like(keyword))
				: getJdbcOperations().queryForObject(sql, Long.class);
		return (total != null) ? total : 0L;
	}

	/**
	 * 一页客户端（含审计字段），<b>单条 SQL</b> 取回全部列。
	 *
	 * <p>返回的 {@link ClientRow} 已包含列表页需要的所有字段，
	 * 调用方不需要再按 id 逐条回查。</p>
	 */
	public List<ClientRow> findPage(String keyword, int limit, int offset) {
		boolean filtered = StringUtils.hasText(keyword);
		String sql = "SELECT * FROM " + TABLE + (filtered ? KEYWORD_WHERE : "") + ORDER_BY + " LIMIT ? OFFSET ?";
		Object[] args = filtered
				? new Object[] { like(keyword), like(keyword), limit, offset }
				: new Object[] { limit, offset };
		return getJdbcOperations().query(sql, this.clientRowMapper, args);
	}

	/** 按 {@code client_id} 取整行（含审计字段），单条 SQL。 */
	public Optional<ClientRow> findRowByClientId(String clientId) {
		List<ClientRow> rows = getJdbcOperations().query(
				"SELECT * FROM " + TABLE + " WHERE client_id = ?", this.clientRowMapper, clientId);
		return rows.isEmpty() ? Optional.empty() : Optional.of(rows.getFirst());
	}

	/**
	 * 按回调地址精确反查 {@code client_id}。
	 *
	 * <p>只取 {@code client_id} 与 {@code redirect_uris} 两列做内存比对（回调地址是小集合，
	 * 一个客户端通常只有一条），命中后由调用方按 id 取整行。逗号切分复用官方同一个工具方法
	 * {@code StringUtils.commaDelimitedListToSet}，匹配语义与运行期反序列化完全一致。</p>
	 */
	public Optional<String> findClientIdByRedirectUri(String redirectUri) {
		List<RedirectUrisRow> rows = getJdbcOperations().query(
				"SELECT client_id, redirect_uris FROM " + TABLE + ORDER_BY,
				(rs, rowNum) -> new RedirectUrisRow(rs.getString("client_id"),
						StringUtils.commaDelimitedListToSet(rs.getString("redirect_uris"))));
		return rows.stream()
			.filter((row) -> row.redirectUris().contains(redirectUri))
			.map(RedirectUrisRow::clientId)
			.findFirst();
	}

	private static String like(String keyword) {
		return "%" + keyword.trim() + "%";
	}

	private static Instant toInstant(ResultSet rs, String column) throws SQLException {
		Timestamp timestamp = rs.getTimestamp(column);
		return (timestamp != null) ? timestamp.toInstant() : null;
	}

	/**
	 * 一行完整客户端：官方 {@link RegisteredClient} + 本项目追加的四个审计列。
	 *
	 * <p>审计列不在 SAS 的映射范围内（也不在其 INSERT/UPDATE 语句里），
	 * 但列表与详情都要展示，所以在同一次查询里一并取出。</p>
	 */
	public record ClientRow(RegisteredClient client, String createdBy, Instant createdAt, String updatedBy,
			Instant updatedAt) {
	}

	/** 反查用的最小投影。 */
	private record RedirectUrisRow(String clientId, Set<String> redirectUris) {
	}

}
