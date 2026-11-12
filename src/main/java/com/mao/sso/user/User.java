package com.mao.sso.user;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import com.mao.sso.common.BaseEntity;
import lombok.Getter;
import lombok.Setter;

/**
 * 用户领域对象（纯 POJO，由 MyBatis 映射）。
 *
 * <p>密码仅以 Argon2id 哈希形式存储（password_hash），不存在明文密码。</p>
 *
 * <p>账户状态语义：</p>
 * <ul>
 *   <li>{@code enabled}：账户是否启用；</li>
 *   <li>{@code accountLocked}：是否被锁定（如连续登录失败、管理员操作）；</li>
 *   <li>{@code accountExpired}：账户本身是否过期（如外包/临时账号）；</li>
 *   <li>{@code credentialsExpiredAt}：密码到期时间，为空表示永不过期。
 *       到期后登录直接被拒绝（映射为 Spring Security 的 credentialsExpired）；</li>
 *   <li>{@code mustChangePassword}：软标记，登录成功后引导用户自助改密，不阻断登录。</li>
 * </ul>
 *
 * <p><b>只使用 {@code @Getter} / {@code @Setter}，禁止使用 {@code @Data}：</b>
 * 实体是可变对象且 {@code passwordHash} 属于敏感字段，{@code @Data} 生成的
 * {@code toString()} / {@code equals()} 既会泄漏哈希值，也会因可变字段导致集合行为异常。</p>
 *
 * <p>本类无 {@code final} 字段：MyBatis 依赖无参构造 + setter 映射，
 * 若引入 {@code final} 字段，Lombok 将只生成全参构造，映射会直接失败。</p>
 */
@Getter
@Setter
public class User extends BaseEntity {

	private Integer id;

	private String username;

	private String email;

	/** 手机号（可空）。 */
	private String phone;

	/** 头像地址（可空）。 */
	private String avatar;

	/** Argon2id 哈希值，永不为明文。 */
	private String passwordHash;

	private String displayName;

	private boolean enabled = true;

	private boolean accountLocked = false;

	private boolean accountExpired = false;

	/** 上次登录时间（可空）。 */
	private Instant lastLoginAt;

	/** 是否需要在下次登录后修改密码。 */
	private boolean mustChangePassword = false;

	/** 密码到期时间，为空表示永不过期。 */
	private Instant credentialsExpiredAt;

	/** 角色列表；分页查询时不填充，详情/登录查询时填充。 */
	private List<Role> roles = new ArrayList<>();

	/**
	 * 手写 setter：保持「永不置空」的既有语义。
	 *
	 * <p>Lombok 检测到同名方法后会跳过生成，因此这里必须保留，
	 * 否则 {@code getRoleCodes()} 会在 roles 为 null 时 NPE。</p>
	 */
	public void setRoles(List<Role> roles) {
		this.roles = (roles != null) ? roles : new ArrayList<>();
	}

	/** 密码是否已过期（为空表示永不过期）。 */
	public boolean isCredentialsExpired() {
		return this.credentialsExpiredAt != null && !this.credentialsExpiredAt.isAfter(Instant.now());
	}

	/** 角色码列表，便于组装 JWT claims 与权限。 */
	public List<String> getRoleCodes() {
		return this.roles.stream().map(Role::getCode).toList();
	}

}
