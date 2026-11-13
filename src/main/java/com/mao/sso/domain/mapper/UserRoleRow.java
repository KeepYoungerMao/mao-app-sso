package com.mao.sso.domain.mapper;

import lombok.Getter;
import lombok.Setter;

/**
 * 用户-角色关联查询的扁平结果行。
 *
 * <p>用于「先分页查用户、再批量查角色」的两段式组装，
 * 避免 join + limit 导致一个用户的多行角色被分页截断。</p>
 *
 * <p>MyBatis 通过 {@code userRoleRowMap} 逐列映射，依赖无参构造 + setter。</p>
 */
@Getter
@Setter
public class UserRoleRow {

	private Integer userId;

	private Integer roleId;

	private String roleCode;

	private String roleName;

}
