package com.mao.sso.common.page;

import lombok.Getter;
import lombok.Setter;

/**
 * 公共分页查询参数。
 *
 * <p>{@code recount} 与 {@code lastHitCount} 的配合逻辑（管理端列表翻页省一次 count 查询）：</p>
 * <ul>
 *   <li>{@code recount=true}（默认）：后端执行 count SQL，返回真实总数；</li>
 *   <li>{@code recount=false} 且 {@code lastHitCount != null}：直接复用调用方上次拿到的总数，
 *       跳过 count SQL —— 适用于「过滤条件未变、仅翻页」的场景；</li>
 *   <li>{@code recount=false} 但 {@code lastHitCount == null}：视为参数异常，降级为执行 count，
 *       避免返回 total=0 让前端误判为空列表。</li>
 * </ul>
 */
@Getter
@Setter
public class PageQuery {

	private static final int DEFAULT_PAGE_SIZE = 20;

	private static final int MAX_PAGE_SIZE = 200;

	private int pageNum = 1;

	private int pageSize = DEFAULT_PAGE_SIZE;

	private boolean recount = true;

	/** 上次查询命中的总数，由调用方回传；仅 recount=false 时使用。 */
	private Integer lastHitCount;

	/** 页码归一并计算 SQL 偏移量（从 0 开始）。 */
	public int offset() {
		return (normalizedPageNum() - 1) * normalizedPageSize();
	}

	public int limit() {
		return normalizedPageSize();
	}

	public int normalizedPageNum() {
		return (this.pageNum < 1) ? 1 : this.pageNum;
	}

	public int normalizedPageSize() {
		if (this.pageSize < 1) {
			return DEFAULT_PAGE_SIZE;
		}
		return Math.min(this.pageSize, MAX_PAGE_SIZE);
	}

}
