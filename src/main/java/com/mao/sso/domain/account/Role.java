package com.mao.sso.domain.account;

import com.mao.sso.domain.support.BaseEntity;
import lombok.Getter;
import lombok.Setter;

/**
 * 角色领域对象（纯 POJO，由 MyBatis 映射）。
 *
 * <p>角色码（code）即 Spring Security 权限标识，约定以 ROLE_ 前缀命名。</p>
 *
 * <p>注意：角色与用户的关联由中间表 {@code user_roles} 维护，
 * 本对象不再持有反向集合（MyBatis 不做双向导航）。</p>
 */
@Getter
@Setter
public class Role extends BaseEntity {

	private Integer id;

	private String code;

	private String name;

	private String description;

}
