package com.mao.sso.user;

import java.util.LinkedHashSet;
import java.util.Set;

import com.mao.sso.common.BaseEntity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * 用户实体。密码仅以 Argon2id 哈希形式存储（password_hash），不存在明文密码。
 *
 * <p>账户四态（enabled / account_locked / account_expired / credentials_expired）
 * 与 Spring Security UserDetails 契约一一对应，由 {@link com.mao.sso.security.SsoUserDetails} 适配。</p>
 */
@Entity
@Table(name = "users", uniqueConstraints = {
		@UniqueConstraint(name = "uk_users_username", columnNames = "username"),
		@UniqueConstraint(name = "uk_users_email", columnNames = "email") })
public class User extends BaseEntity {

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@NotBlank
	@Size(max = 50)
	@Pattern(regexp = "^[a-zA-Z0-9][a-zA-Z0-9._-]{1,49}$", message = "用户名只能包含字母、数字、点、下划线、连字符，且长度 2-50")
	@Column(name = "username", nullable = false, length = 50)
	private String username;

	@NotBlank
	@Email
	@Size(max = 255)
	@Column(name = "email", nullable = false, length = 255)
	private String email;

	/** Argon2id 哈希值，永不为明文。 */
	@NotBlank
	@Size(max = 255)
	@Column(name = "password_hash", nullable = false, length = 255)
	private String passwordHash;

	@NotBlank
	@Size(max = 100)
	@Column(name = "display_name", nullable = false, length = 100)
	private String displayName;

	@Column(name = "enabled", nullable = false)
	private boolean enabled = true;

	@Column(name = "account_locked", nullable = false)
	private boolean accountLocked = false;

	@Column(name = "account_expired", nullable = false)
	private boolean accountExpired = false;

	@Column(name = "credentials_expired", nullable = false)
	private boolean credentialsExpired = false;

	@ManyToMany(fetch = jakarta.persistence.FetchType.LAZY)
	@JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"),
			inverseJoinColumns = @JoinColumn(name = "role_id"))
	private Set<Role> roles = new LinkedHashSet<>();

	public Long getId() {
		return this.id;
	}

	public String getUsername() {
		return this.username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getEmail() {
		return this.email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getPasswordHash() {
		return this.passwordHash;
	}

	public void setPasswordHash(String passwordHash) {
		this.passwordHash = passwordHash;
	}

	public String getDisplayName() {
		return this.displayName;
	}

	public void setDisplayName(String displayName) {
		this.displayName = displayName;
	}

	public boolean isEnabled() {
		return this.enabled;
	}

	public void setEnabled(boolean enabled) {
		this.enabled = enabled;
	}

	public boolean isAccountLocked() {
		return this.accountLocked;
	}

	public void setAccountLocked(boolean accountLocked) {
		this.accountLocked = accountLocked;
	}

	public boolean isAccountExpired() {
		return this.accountExpired;
	}

	public void setAccountExpired(boolean accountExpired) {
		this.accountExpired = accountExpired;
	}

	public boolean isCredentialsExpired() {
		return this.credentialsExpired;
	}

	public void setCredentialsExpired(boolean credentialsExpired) {
		this.credentialsExpired = credentialsExpired;
	}

	public Set<Role> getRoles() {
		return this.roles;
	}

	public void setRoles(Set<Role> roles) {
		this.roles = roles;
	}

}
