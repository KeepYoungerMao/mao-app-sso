package com.mao.sso.user;

import java.util.LinkedHashSet;
import java.util.Set;

import com.mao.sso.common.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * 角色实体。角色码（code）即 Spring Security 权限标识，约定以 ROLE_ 前缀命名。
 */
@Entity
@Table(name = "roles", uniqueConstraints = {
		@UniqueConstraint(name = "uk_roles_code", columnNames = "code") })
public class Role extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Size(max = 50)
	@Pattern(regexp = "^ROLE_[A-Z0-9_]+$", message = "角色码必须以 ROLE_ 前缀且全大写")
	@Column(name = "code", nullable = false, length = 50)
	private String code;

	@NotBlank
	@Size(max = 100)
	@Column(name = "name", nullable = false, length = 100)
	private String name;

	@Size(max = 255)
	@Column(name = "description", length = 255)
	private String description;

	@ManyToMany(mappedBy = "roles", fetch = jakarta.persistence.FetchType.LAZY)
	private Set<User> users = new LinkedHashSet<>();

	public Long getId() {
		return this.id;
	}

	public String getCode() {
		return this.code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getName() {
		return this.name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getDescription() {
		return this.description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public Set<User> getUsers() {
		return this.users;
	}

}
