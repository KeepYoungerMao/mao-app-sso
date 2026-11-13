package com.mao.sso.domain.error;

import lombok.Getter;

import org.springframework.http.HttpStatus;

/**
 * 业务错误码（全局唯一定义处）。
 *
 * <p>分段约定：</p>
 * <ul>
 *   <li>{@code 0}：成功；</li>
 *   <li>{@code 1xxxx}：客户端错误（对应 4xx）；</li>
 *   <li>{@code 5xxxx}：服务端错误（对应 5xx）。</li>
 * </ul>
 *
 * <p>HTTP status 规则：能映射上的（400/401/403/404/405/409/415）用映射值；
 * 无法映射业务含义的统一 500。响应 body 中的 {@code code} 恒为本枚举的数字码，
 * 与 HTTP status 解耦 —— 调用方应以 body 的 code 为准做分支判断。</p>
 */
@Getter
public enum ErrorCode {

	/** 成功。 */
	SUCCESS(0, HttpStatus.OK, "ok"),

	/** 请求参数不合法（可预期的业务校验失败、JSON 格式错误、缺少必填参数）。 */
	INVALID_REQUEST(10000, HttpStatus.BAD_REQUEST, "请求参数不合法"),

	/** 资源不存在（按 id / client_id / username 查不到）。 */
	RESOURCE_NOT_FOUND(10001, HttpStatus.NOT_FOUND, "资源不存在"),

	/** 资源重复或唯一性冲突（用户名/邮箱/client_id/redirect_uri 已存在）。 */
	DUPLICATE_RESOURCE(10002, HttpStatus.CONFLICT, "资源已存在或与现有数据冲突"),

	/** 操作不被允许（删除最后一个管理员、删除管理控制台自身客户端等）。 */
	OPERATION_NOT_ALLOWED(10003, HttpStatus.CONFLICT, "操作不被允许"),

	/** 未认证或凭证已过期（非 HTML 请求命中登录拦截时返回）。 */
	UNAUTHORIZED(10401, HttpStatus.UNAUTHORIZED, "未认证或凭证已过期"),

	/** 已认证但没有访问权限。 */
	ACCESS_DENIED(10403, HttpStatus.FORBIDDEN, "没有访问权限"),

	/** 请求的地址不存在（框架 404：无匹配路由、静态资源未命中）。 */
	REQUEST_NOT_FOUND(10404, HttpStatus.NOT_FOUND, "请求的地址不存在"),

	/** 请求方法不支持（如 GET 访问只接受 POST 的接口）。 */
	METHOD_NOT_ALLOWED(10405, HttpStatus.METHOD_NOT_ALLOWED, "请求方法不支持"),

	/** 请求内容类型不支持。 */
	UNSUPPORTED_MEDIA_TYPE(10415, HttpStatus.UNSUPPORTED_MEDIA_TYPE, "请求内容类型不支持"),

	/** 服务器内部错误（所有未分类异常的兜底）。 */
	INTERNAL_ERROR(50000, HttpStatus.INTERNAL_SERVER_ERROR, "服务器内部错误");

	private final int code;

	private final HttpStatus httpStatus;

	private final String defaultMessage;

	ErrorCode(int code, HttpStatus httpStatus, String defaultMessage) {
		this.code = code;
		this.httpStatus = httpStatus;
		this.defaultMessage = defaultMessage;
	}

}
