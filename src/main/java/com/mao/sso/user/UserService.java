package com.mao.sso.user;

import java.util.LinkedHashSet;
import java.util.Optional;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.mao.sso.exception.DuplicateResourceException;
import com.mao.sso.exception.ResourceNotFoundException;

/**
 * 用户业务逻辑：创建、状态管理、角色维护。Controller 不直接访问 Repository。
 */
@Service
public class UserService {

	public static final String ROLE_USER = "ROLE_USER";

	public static final String ROLE_ADMIN = "ROLE_ADMIN";

	private final UserRepository userRepository;

	private final RoleRepository roleRepository;

	private final PasswordEncoder passwordEncoder;

	public UserService(UserRepository userRepository, RoleRepository roleRepository,
			PasswordEncoder passwordEncoder) {
		this.userRepository = userRepository;
		this.roleRepository = roleRepository;
		this.passwordEncoder = passwordEncoder;
	}

	/**
	 * 创建用户（密码明文仅在本方法内存在，立即哈希后持久化）。
	 */
	@Transactional
	public User createUser(String username, String email, String rawPassword, String displayName,
			Set<String> roleCodes) {
		if (this.userRepository.existsByUsername(username)) {
			throw new DuplicateResourceException("用户名已存在: " + username);
		}
		if (this.userRepository.existsByEmail(email)) {
			throw new DuplicateResourceException("邮箱已存在: " + email);
		}
		User user = new User();
		user.setUsername(username);
		user.setEmail(email);
		user.setDisplayName(displayName);
		user.setPasswordHash(this.passwordEncoder.encode(rawPassword));
		Set<Role> roles = new LinkedHashSet<>();
		for (String roleCode : roleCodes) {
			roles.add(findRoleByCode(roleCode));
		}
		user.setRoles(roles);
		return this.userRepository.save(user);
	}

	@Transactional(readOnly = true)
	public Optional<User> findByUsername(String username) {
		return this.userRepository.findByUsername(username);
	}

	@Transactional(readOnly = true)
	public User requireUser(String username) {
		return this.userRepository.findByUsernameWithRoles(username)
			.orElseThrow(() -> new ResourceNotFoundException("用户不存在: " + username));
	}

	/**
	 * 查询全部用户（含角色，用于管理页列表）。
	 */
	@Transactional(readOnly = true)
	public java.util.List<User> findAllUsers() {
		return this.userRepository.findAllWithRoles();
	}

	@Transactional
	public void updatePassword(Long userId, String newRawPassword) {
		User user = this.userRepository.findById(userId)
			.orElseThrow(() -> new ResourceNotFoundException("用户不存在: " + userId));
		user.setPasswordHash(this.passwordEncoder.encode(newRawPassword));
		this.userRepository.save(user);
	}

	@Transactional
	public void updateStatus(Long userId, boolean enabled, boolean locked) {
		User user = this.userRepository.findById(userId)
			.orElseThrow(() -> new ResourceNotFoundException("用户不存在: " + userId));
		user.setEnabled(enabled);
		user.setAccountLocked(locked);
		this.userRepository.save(user);
	}

	@Transactional
	public void updateDisplayName(Long userId, String displayName) {
		User user = this.userRepository.findById(userId)
			.orElseThrow(() -> new ResourceNotFoundException("用户不存在: " + userId));
		user.setDisplayName(displayName);
		this.userRepository.save(user);
	}

	@Transactional(readOnly = true)
	public Role findRoleByCode(String roleCode) {
		return this.roleRepository.findByCode(roleCode)
			.orElseThrow(() -> new ResourceNotFoundException("角色不存在: " + roleCode));
	}

	/**
	 * 确保系统预置角色存在（幂等）。
	 */
	@Transactional
	public void ensureRole(String code, String name, String description) {
		Optional<Role> existing = this.roleRepository.findByCode(code);
		if (existing.isPresent()) {
			return;
		}
		Role role = new Role();
		role.setCode(code);
		role.setName(name);
		role.setDescription(description);
		this.roleRepository.save(role);
	}

}
