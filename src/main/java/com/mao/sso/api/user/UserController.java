package com.mao.sso.api.user;

import jakarta.validation.Valid;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mao.sso.api.dto.AdminRequests.IdRequest;
import com.mao.sso.api.dto.AdminRequests.UserBindRolesRequest;
import com.mao.sso.api.dto.AdminRequests.UserCreateRequest;
import com.mao.sso.api.dto.AdminRequests.UserPasswordRequest;
import com.mao.sso.api.dto.AdminRequests.UserRenewRequest;
import com.mao.sso.api.dto.AdminRequests.UserUpdateRequest;
import com.mao.sso.api.dto.UserPageRequest;
import com.mao.sso.api.dto.AdminViews.CreatedUserView;
import com.mao.sso.api.dto.AdminViews.DeletedView;
import com.mao.sso.api.dto.AdminViews.OneTimePasswordView;
import com.mao.sso.api.dto.AdminViews.UserView;
import com.mao.sso.domain.support.PageResult;
import com.mao.sso.api.dto.CreatedUser;
import com.mao.sso.domain.account.User;

/**
 * 用户管理 API。
 *
 * <p>设计约定：</p>
 * <ul>
 *   <li>全部使用 POST + {@code application/json}（业务动作型接口，不做 REST 方法语义区分）；</li>
 *   <li>成功直接返回业务数据，失败由 {@code GlobalExceptionHandler} 输出 RFC 7807 ProblemDetail；</li>
 *   <li>密码类接口的明文只在响应中出现一次，服务端仅保存 Argon2id 哈希。</li>
 * </ul>
 */
@RestController
@RequestMapping(path = "/api/v1/admin/user", produces = MediaType.APPLICATION_JSON_VALUE)
public class UserController {

	private final UserService userService;

	public UserController(UserService userService) {
		this.userService = userService;
	}

	/** 用户分页查询。 */
	@PostMapping("/page")
	public PageResult<UserView> page(@RequestBody(required = false) UserPageRequest request) {
		UserPageRequest query = (request != null) ? request : new UserPageRequest();
		PageResult<User> page = this.userService.pageUsers(query, query.getKeyword(), query.getEnabled(),
				query.getLocked());
		return new PageResult<>(page.getPageNum(), page.getPageSize(), page.getTotal(),
				page.getRecords().stream().map(UserView::from).toList());
	}

	/** 用户详情。 */
	@PostMapping("/detail")
	public UserView detail(@Valid @RequestBody IdRequest request) {
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 创建用户：服务端生成初始密码，响应中一次性返回。 */
	@PostMapping("/create")
	public CreatedUserView create(@Valid @RequestBody UserCreateRequest request) {
		CreatedUser created = this.userService.createUserByAdmin(request.username(), request.email(),
				request.displayName(), request.phone(), request.avatar(), request.roleCodes());
		return new CreatedUserView(created.id(), created.username(), created.rawPassword());
	}

	/** 更新用户资料（email / phone / avatar / display_name）。 */
	@PostMapping("/update")
	public UserView update(@Valid @RequestBody UserUpdateRequest request) {
		this.userService.updateProfile(request.id(), request.email(), request.phone(), request.avatar(),
				request.displayName());
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 管理员为指定用户设置新密码（视为已完成改密，清除 must_change_password）。 */
	@PostMapping("/change-password")
	public UserView changePassword(@Valid @RequestBody UserPasswordRequest request) {
		this.userService.changePassword(request.id(), request.newPassword());
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 重置密码：服务端生成随机密码，响应中一次性返回。 */
	@PostMapping("/reset-password")
	public OneTimePasswordView resetPassword(@Valid @RequestBody IdRequest request) {
		User user = this.userService.requireById(request.id());
		String password = this.userService.resetPassword(request.id());
		return new OneTimePasswordView(user.getId(), user.getUsername(), password);
	}

	/** 密码续期：credentialsExpiredAt 为空表示永不过期。 */
	@PostMapping("/renew")
	public UserView renew(@Valid @RequestBody UserRenewRequest request) {
		this.userService.renewCredentials(request.id(), request.credentialsExpiredAt());
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 锁定用户。 */
	@PostMapping("/lock")
	public UserView lock(@Valid @RequestBody IdRequest request) {
		this.userService.setLocked(request.id(), true);
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 解锁用户。 */
	@PostMapping("/unlock")
	public UserView unlock(@Valid @RequestBody IdRequest request) {
		this.userService.setLocked(request.id(), false);
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 启用用户。 */
	@PostMapping("/enable")
	public UserView enable(@Valid @RequestBody IdRequest request) {
		this.userService.setEnabled(request.id(), true);
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 停用用户。 */
	@PostMapping("/disable")
	public UserView disable(@Valid @RequestBody IdRequest request) {
		this.userService.setEnabled(request.id(), false);
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 角色绑定（全量替换）。 */
	@PostMapping("/bind-roles")
	public UserView bindRoles(@Valid @RequestBody UserBindRolesRequest request) {
		this.userService.bindRoles(request.id(), request.roleCodes());
		return UserView.from(this.userService.requireById(request.id()));
	}

	/** 物理删除用户。 */
	@PostMapping("/delete")
	public DeletedView delete(@Valid @RequestBody IdRequest request) {
		this.userService.deleteUser(request.id());
		return new DeletedView(request.id(), true);
	}

}
