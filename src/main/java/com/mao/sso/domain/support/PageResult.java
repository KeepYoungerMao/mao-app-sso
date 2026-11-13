package com.mao.sso.domain.support;

import java.util.List;

import lombok.Getter;

/**
 * 公共分页响应体。
 *
 * <p>不可变对象：全部字段 {@code final}，只提供 {@code @Getter}（字段为 {@code final} 时
 * Lombok 不生成 setter），保留 {@code getPageNum()} 等既有方法签名，调用方无需改动。</p>
 *
 * @param <T> 记录类型
 */
@Getter
public class PageResult<T> {

	private final int pageNum;

	private final int pageSize;

	private final long total;

	private final List<T> records;

	public PageResult(int pageNum, int pageSize, long total, List<T> records) {
		this.pageNum = pageNum;
		this.pageSize = pageSize;
		this.total = total;
		this.records = (records != null) ? records : List.of();
	}

}
