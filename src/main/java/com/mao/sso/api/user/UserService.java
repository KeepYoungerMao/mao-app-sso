package com.mao.sso.api.user;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import com.mao.sso.api.dto.CreatedUser;
import com.mao.sso.domain.account.Role;
import com.mao.sso.domain.account.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.StringUtils;

import com.mao.sso.domain.support.AuditContext;
import com.mao.sso.domain.support.PageQuery;
import com.mao.sso.domain.support.PageResult;
import com.mao.sso.domain.support.PasswordGenerator;
import com.mao.sso.domain.error.DuplicateResourceException;
import com.mao.sso.domain.error.InvalidRequestException;
import com.mao.sso.domain.error.OperationNotAllowedException;
import com.mao.sso.domain.error.ResourceNotFoundException;
import com.mao.sso.domain.mapper.RoleMapper;
import com.mao.sso.domain.mapper.UserMapper;
import com.mao.sso.domain.mapper.UserRoleRow;

/**
 * 用户业务逻辑（基于 MyBatis Mapper）。
 *
 * <p>职责边界：</p>
 * <ul>
 *   <li>只做业务规则与事务边界，SQL 全部在 {@code resources/mapper/*.xml}；</li>
 *   <li>密码一律 Argon2id 哈希后落库，明文仅在返回给调用方的那一次出现；</li>
 *   <li>审计字段由 {@link AuditContext} 解析当前操作人后显式写入。</li>
 * </ul>
 *
 * <p>最后管理员保护：删除 / 停用 / 锁定操作前会统计「其余启用且未锁定的管理员」数量，
 * 为 0 时拒绝执行，避免系统失去可登录的管理员。</p>
 */
@Service
public class UserService {

	/** 默认业务角色：普通客户（角色 code 即业务标识，小写）。 */
	public static final String ROLE_CUSTOMER = "customer";

	/** 管理员角色：可访问管理 API。 */
	public static final String ROLE_ADMIN = "admin";

	private final UserMapper userMapper;

	private final RoleMapper roleMapper;

	private final PasswordEncoder passwordEncoder;

	public UserService(UserMapper userMapper, RoleMapper roleMapper, PasswordEncoder passwordEncoder) {
		this.userMapper = userMapper;
		this.roleMapper = roleMapper;
		this.passwordEncoder = passwordEncoder;
	}

	// ==================== 查询 ====================

	@Transactional(readOnly = true)
	public Optional<User> findByUsername(String username) {
		return this.userMapper.findByUsername(username);
	}

	/**
	 * 按用户名查询并填充角色，不存在返回空。
	 *
	 * <p>与 {@link #findByUsername(String)} 的区别是带角色（多一次 join），
	 * 供签发 Token 时读取 {@code roles} claim 使用。同样是为了让调用方不必
	 * 直接依赖 {@code mapper} 子包。</p>
	 */
	@Transactional(readOnly = true)
	public Optional<User> findByUsernameWithRoles(String username) {
		return this.userMapper.findByUsernameWithRoles(username);
	}

	/**
	 * 登录查询：用户名或邮箱均可，结果带角色。
	 *
	 * <p>入参归一化（trim、null 转空）在这里做，调用方不需要重复处理。
	 * 供认证服务器构造 {@code UserDetails} 使用 —— 调用方因此不必直接依赖
	 * {@code mapper} 子包，持久层实现细节不会漏到接口层。</p>
	 */
	@Transactional(readOnly = true)
	public Optional<User> findByIdentifier(String identifier) {
		String normalized = (identifier == null) ? "" : identifier.trim();
		return normalized.isEmpty() ? Optional.empty()
				: this.userMapper.findByIdentifierWithRoles(normalized);
	}

	/** 按用户名查询并填充角色（登录、详情使用）。 */
	@Transactional(readOnly = true)
	public User requireUser(String username) {
		return this.userMapper.findByUsernameWithRoles(username)
			.orElseThrow(() -> new ResourceNotFoundException("用户不存在: " + username));
	}

	/** 按主键查询并填充角色。 */
	@Transactional(readOnly = true)
	public User requireById(Integer id) {
		return this.userMapper.findByIdWithRoles(id)
			.orElseThrow(() -> new ResourceNotFoundException("用户不存在: " + id));
	}

	@Transactional(readOnly = true)
	public List<User> findAllUsers() {
		return this.userMapper.findAllWithRoles();
	}

	/**
	 * 用户分页查询。
	 *
	 * <p>两段式组装：先分页查主表（避免 join + limit 截断角色行），再按 user_id 批量查角色。</p>
	 */
	@Transactional(readOnly = true)
	public PageResult<User> pageUsers(PageQuery query, String keyword, Boolean enabled, Boolean locked) {
		long total;
		if (!query.isRecount() && query.getLastHitCount() != null) {
			// 过滤条件未变、仅翻页：跳过 count SQL
			total = query.getLastHitCount();
		}
		else {
			total = this.userMapper.countPage(keyword, enabled, locked);
		}

		int offset = query.offset();
		List<User> users = (offset >= total) ? List.of()
				: this.userMapper.selectPage(keyword, enabled, locked, offset, query.limit());

		attachRoles(users);
		return new PageResult<>(query.normalizedPageNum(), query.normalizedPageSize(), total, users);
	}

	private void attachRoles(List<User> users) {
		if (users.isEmpty()) {
			return;
		}
		List<Integer> ids = users.stream().map(User::getId).toList();
		Map<Integer, List<Role>> rolesByUser = new LinkedHashMap<>();
		for (UserRoleRow row : this.userMapper.findRolesByUserIds(ids)) {
			Role role = new Role();
			role.setId(row.getRoleId());
			role.setCode(row.getRoleCode());
			role.setName(row.getRoleName());
			rolesByUser.computeIfAbsent(row.getUserId(), (key) -> new ArrayList<>()).add(role);
		}
		for (User user : users) {
			user.setRoles(rolesByUser.getOrDefault(user.getId(), new ArrayList<>()));
		}
	}

	// ==================== 创建 ====================

	/**
	 * 创建用户（指定明文密码）。
	 *
	 * <p>用于启动初始化与测试；管理端创建请用 {@link #createUserByAdmin}（密码由服务端生成）。</p>
	 */
	@Transactional
	public User createUser(String username, String email, String rawPassword, String displayName,
			Collection<String> roleCodes) {
		return doCreateUser(username, email, null, null, rawPassword, displayName, roleCodes, false);
	}

	/**
	 * 管理员创建用户：服务端生成随机密码，返回明文一次，并置「下次登录需改密」。
	 */
	@Transactional
	public CreatedUser createUserByAdmin(String username, String email, String displayName, String phone,
                                         String avatar, Collection<String> roleCodes) {
		String rawPassword = PasswordGenerator.generate();
		User user = doCreateUser(username, email, phone, avatar, rawPassword, displayName, roleCodes, true);
		return new CreatedUser(user.getId(), user.getUsername(), rawPassword);
	}

	private User doCreateUser(String username, String email, String phone, String avatar, String rawPassword,
			String displayName, Collection<String> roleCodes, boolean mustChangePassword) {

		if (!StringUtils.hasText(username)) {
			throw new InvalidRequestException("用户名不能为空");
		}
		if (this.userMapper.countByUsername(username, null) > 0) {
			throw new DuplicateResourceException("用户名已存在: " + username);
		}
		if (StringUtils.hasText(email) && this.userMapper.countByEmail(email, null) > 0) {
			throw new DuplicateResourceException("邮箱已存在: " + email);
		}

		Set<String> codes = normalizeRoleCodes(roleCodes);
		List<Integer> roleIds = resolveRoleIds(codes);

		User user = new User();
		user.setUsername(username);
		user.setEmail(email);
		user.setPhone(phone);
		user.setAvatar(avatar);
		user.setDisplayName(StringUtils.hasText(displayName) ? displayName : username);
		user.setPasswordHash(this.passwordEncoder.encode(rawPassword));
		user.setEnabled(true);
		user.setAccountLocked(false);
		user.setAccountExpired(false);
		user.setMustChangePassword(mustChangePassword);
		user.setCreatedBy(AuditContext.currentUser());
		user.setUpdatedBy(AuditContext.currentUser());

		this.userMapper.insert(user);
		if (!roleIds.isEmpty()) {
			this.userMapper.insertUserRoles(user.getId(), roleIds);
		}
		user.setRoles(loadRoles(roleIds));
		return user;
	}

	// ==================== 更新 ====================

	@Transactional
	public void updateProfile(Integer id, String email, String phone, String avatar, String displayName) {
		User user = requireExisting(id);
		if (StringUtils.hasText(email) && this.userMapper.countByEmail(email, id) > 0) {
			throw new DuplicateResourceException("邮箱已存在: " + email);
		}
		String finalDisplayName = StringUtils.hasText(displayName) ? displayName : user.getDisplayName();
		this.userMapper.updateProfile(id, email, phone, avatar, finalDisplayName, AuditContext.currentUser());
	}

	/** 管理员指定新密码：视为已完成改密，清除「必须改密」标记。 */
	@Transactional
	public void changePassword(Integer id, String rawPassword) {
		requireExisting(id);
		validatePassword(rawPassword);
		this.userMapper.updatePassword(id, this.passwordEncoder.encode(rawPassword), false,
				AuditContext.currentUser());
	}

	/**
	 * 重置密码：服务端生成随机密码，返回明文一次，并置「下次登录需改密」。
	 */
	@Transactional
	public String resetPassword(Integer id) {
		requireExisting(id);
		String rawPassword = PasswordGenerator.generate();
		this.userMapper.updatePassword(id, this.passwordEncoder.encode(rawPassword), true,
				AuditContext.currentUser());
		return rawPassword;
	}

	@Transactional
	public void updateStatus(Integer id, boolean enabled, boolean locked) {
		User user = requireExisting(id);
		if ((!enabled || locked) && isActiveAdmin(user)) {
			ensureOtherActiveAdminExists(id, enabled ? "锁定" : "停用");
		}
		this.userMapper.updateStatus(id, enabled, locked, AuditContext.currentUser());
	}

	@Transactional
	public void setEnabled(Integer id, boolean enabled) {
		User user = requireExisting(id);
		if (!enabled && isActiveAdmin(user)) {
			ensureOtherActiveAdminExists(id, "停用");
		}
		this.userMapper.updateStatus(id, enabled, user.isAccountLocked(), AuditContext.currentUser());
	}

	@Transactional
	public void setLocked(Integer id, boolean locked) {
		User user = requireExisting(id);
		if (locked && isActiveAdmin(user)) {
			ensureOtherActiveAdminExists(id, "锁定");
		}
		this.userMapper.updateStatus(id, user.isEnabled(), locked, AuditContext.currentUser());
	}

	/** 密码续期：{@code expiredAt} 为空表示永不过期。 */
	@Transactional
	public void renewCredentials(Integer id, Instant expiredAt) {
		requireExisting(id);
		this.userMapper.updateCredentialsExpiredAt(id, expiredAt, AuditContext.currentUser());
	}

	/** 角色绑定：全量替换。 */
	@Transactional
	public void bindRoles(Integer id, Collection<String> roleCodes) {
		requireExisting(id);
		Set<String> codes = normalizeRoleCodes(roleCodes);
		List<Integer> roleIds = resolveRoleIds(codes);
		this.userMapper.deleteUserRoles(id);
		if (!roleIds.isEmpty()) {
			this.userMapper.insertUserRoles(id, roleIds);
		}
	}

	/** 物理删除用户（user_roles 由外键 ON DELETE CASCADE 清理）。 */
	@Transactional
	public void deleteUser(Integer id) {
		User user = requireExisting(id);
		if (isActiveAdmin(user)) {
			ensureOtherActiveAdminExists(id, "删除");
		}
		this.userMapper.deleteById(id);
	}

	/** 记录登录时间（登录成功时调用，不参与审计字段）。 */
	@Transactional
	public void recordLogin(String username) {
		this.userMapper.findByUsername(username)
			.ifPresent((user) -> this.userMapper.updateLastLoginAt(user.getId(), Instant.now()));
	}

	// ==================== 角色 ====================

	@Transactional(readOnly = true)
	public Role findRoleByCode(String code) {
		return this.roleMapper.findByCode(code)
			.orElseThrow(() -> new ResourceNotFoundException("角色不存在: " + code));
	}

	@Transactional(readOnly = true)
	public List<Role> findAllRoles() {
		return this.roleMapper.findAll();
	}

	// ==================== 内部工具 ====================

	private User requireExisting(Integer id) {
		if (id == null) {
			throw new ResourceNotFoundException("用户不存在: null");
		}
		return this.userMapper.findByIdWithRoles(id)
			.orElseThrow(() -> new ResourceNotFoundException("用户不存在: " + id));
	}

	private static boolean isActiveAdmin(User user) {
		return user.getRoleCodes().contains(ROLE_ADMIN) && user.isEnabled() && !user.isAccountLocked();
	}

	private void ensureOtherActiveAdminExists(Integer excludeId, String action) {
		if (this.userMapper.countActiveAdmins(excludeId) == 0) {
			throw new OperationNotAllowedException("不能" + action + "系统最后一个可用管理员");
		}
	}

	private static Set<String> normalizeRoleCodes(Collection<String> roleCodes) {
		Set<String> codes = new LinkedHashSet<>();
		if (roleCodes != null) {
			for (String code : roleCodes) {
				if (StringUtils.hasText(code)) {
					codes.add(code.trim());
				}
			}
		}
		if (codes.isEmpty()) {
			codes.add(ROLE_CUSTOMER);
		}
		return codes;
	}

	private List<Integer> resolveRoleIds(Collection<String> roleCodes) {
		List<Integer> ids = new ArrayList<>(roleCodes.size());
		for (String code : roleCodes) {
			Role role = this.roleMapper.findByCode(code)
				.orElseThrow(() -> new ResourceNotFoundException("角色不存在: " + code));
			ids.add(role.getId());
		}
		return ids;
	}

	private List<Role> loadRoles(List<Integer> roleIds) {
		List<Role> roles = new ArrayList<>(roleIds.size());
		for (Integer roleId : roleIds) {
			this.roleMapper.findById(roleId).ifPresent(roles::add);
		}
		return roles;
	}

	private static void validatePassword(String rawPassword) {
		if (!StringUtils.hasText(rawPassword) || rawPassword.length() < 8 || rawPassword.length() > 64) {
			throw new InvalidRequestException("密码长度必须在 8~64 位之间");
		}
	}

}
