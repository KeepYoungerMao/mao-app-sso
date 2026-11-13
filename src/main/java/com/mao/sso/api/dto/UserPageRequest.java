package com.mao.sso.api.dto;

import com.mao.sso.domain.support.PageQuery;
import lombok.Getter;
import lombok.Setter;

/**
 * 用户分页查询参数。
 *
 * <p>继承 {@link PageQuery} 以获得 pageNum / pageSize / recount / lastHitCount 语义。</p>
 *
 * <p>不用 {@code @Data}：子类自动生成的 {@code equals/hashCode} 默认忽略父类字段，
 * 且此处没有任何值对象语义需求。</p>
 */
@Getter
@Setter
public class UserPageRequest extends PageQuery {

	/** 关键词：匹配用户名 / 邮箱 / 显示名称 / 手机号。 */
	private String keyword;

	/** 是否启用（null 表示不筛选）。 */
	private Boolean enabled;

	/** 是否锁定（null 表示不筛选）。 */
	private Boolean locked;

}
