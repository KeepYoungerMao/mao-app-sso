package com.mao.sso.admin.dto;

import java.time.Instant;
import java.util.List;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * 管理 API 的请求体定义（全部 POST + application/json）。
 *
 * <p>集中在一个容器类里，避免为每个端点创建独立文件；对外 JSON 结构即 record 结构。</p>
 */
public final class AdminRequests {

	private AdminRequests() {
	}

	/** 通用主键请求：详情、锁定、解锁、启用、停用、删除、重置密码。 */
	public record IdRequest(@NotNull(message = "id 不能为空") Integer id) {
	}

	/** 用户创建：密码由服务端生成，调用方不传。 */
	public record UserCreateRequest(
			@NotBlank(message = "用户名不能为空")
			@Pattern(regexp = "^[a-zA-Z0-9][a-zA-Z0-9._-]{1,49}$",
					message = "用户名只能包含字母、数字、点、下划线、连字符，且长度 2-50")
			String username,

			@NotBlank(message = "邮箱不能为空") @Email(message = "邮箱格式不正确") @Size(max = 255) String email,

			@Size(max = 100, message = "显示名称长度不能超过 100") String displayName,

			@Pattern(regexp = "^$|^[0-9+\\-() ]{5,32}$", message = "手机号格式不正确") String phone,

			@Size(max = 500, message = "头像地址长度不能超过 500") String avatar,

			List<String> roleCodes) {
	}

	/** 用户信息更新：仅允许修改资料字段，不涉及账号状态与角色。 */
	public record UserUpdateRequest(
			@NotNull(message = "id 不能为空") Integer id,

			@Email(message = "邮箱格式不正确") @Size(max = 255) String email,

			@Pattern(regexp = "^$|^[0-9+\\-() ]{5,32}$", message = "手机号格式不正确") String phone,

			@Size(max = 500, message = "头像地址长度不能超过 500") String avatar,

			@Size(max = 100, message = "显示名称长度不能超过 100") String displayName) {
	}

	/** 管理员指定新密码。 */
	public record UserPasswordRequest(
			@NotNull(message = "id 不能为空") Integer id,

			@NotBlank(message = "新密码不能为空")
			@Size(min = 8, max = 64, message = "密码长度必须在 8~64 位之间")
			String newPassword) {
	}

	/** 密码续期：credentialsExpiredAt 为空表示永不过期。 */
	public record UserRenewRequest(
			@NotNull(message = "id 不能为空") Integer id,

			Instant credentialsExpiredAt) {
	}

	/** 角色绑定（全量替换）。 */
	public record UserBindRolesRequest(
			@NotNull(message = "id 不能为空") Integer id,

			@NotEmpty(message = "roleCodes 不能为空")
			List<String> roleCodes) {
	}

	/** 客户端主键请求。 */
	public record ClientIdRequest(@NotBlank(message = "clientId 不能为空") String clientId) {
	}

	/** 客户端创建。 */
	public record ClientCreateRequest(
			@NotBlank(message = "clientId 不能为空")
			@Pattern(regexp = "^[a-zA-Z0-9][a-zA-Z0-9._-]{1,63}$",
					message = "clientId 只能包含字母、数字、点、下划线、连字符，且长度 2-64")
			String clientId,

			@Size(max = 200, message = "客户端名称长度不能超过 200") String clientName,

			/** 机密客户端可指定，留空由服务端生成并一次性返回。 */
			String clientSecret,

			@NotEmpty(message = "authenticationMethods 不能为空") List<String> authenticationMethods,

			@NotEmpty(message = "grantTypes 不能为空") List<String> grantTypes,

			/**
			 * 回调地址。<b>项目约定：一个客户端只允许一个 redirect_uri</b>，所以这里是单值而非数组；
			 * 传数组会导致反序列化失败。
			 */
			@NotBlank(message = "redirectUri 不能为空")
			@Size(max = 2000, message = "redirectUri 长度不能超过 2000")
			String redirectUri,

			@NotEmpty(message = "scopes 不能为空") List<String> scopes,

			Boolean requireConsent,

			Boolean requireProofKey) {
	}

	/** 客户端更新：只改可变属性，client_id / 密钥 / 授权类型不可通过本接口变更。 */
	public record ClientUpdateRequest(
			@NotBlank(message = "clientId 不能为空") String clientId,

			@Size(max = 200, message = "客户端名称长度不能超过 200") String clientName,

			/** 留空表示不修改。项目约定一个客户端只允许一个回调地址。 */
			@Size(max = 2000, message = "redirectUri 长度不能超过 2000")
			String redirectUri,

			List<String> scopes,

			Boolean requireConsent,

			Boolean requireProofKey) {
	}

}
