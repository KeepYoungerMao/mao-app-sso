package com.mao.sso.common;

import java.time.Instant;

import lombok.Getter;
import lombok.Setter;

/**
 * 审计字段基类：统一维护创建人 / 创建时间 / 更新人 / 更新时间。
 *
 * <p>纯 POJO（不再是 JPA {@code @MappedSuperclass}），仅供 MyBatis 映射使用。</p>
 *
 * <p>写入策略：</p>
 * <ul>
 *   <li>{@code created_at} / {@code updated_at} 由数据库 {@code CURRENT_TIMESTAMP(6)} 填充，
 *       避免应用与数据库时钟不一致；</li>
 *   <li>{@code created_by} / {@code updated_by} 由 Service 层通过
 *       {@link com.mao.sso.common.audit.AuditContext} 显式写入，便于审计追溯。</li>
 * </ul>
 *
 * <p>子类不要叠加 {@code @Data} / {@code @EqualsAndHashCode}：默认不比较父类字段，
 * 会让仅审计字段不同的两个实体被判定为「相等」。</p>
 */
@Getter
@Setter
public abstract class BaseEntity {

	private Instant createdAt;

	private Instant updatedAt;

	private String createdBy;

	private String updatedBy;

}
