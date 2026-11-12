package com.mao.sso.exception;

import com.fasterxml.jackson.annotation.JsonInclude;

import lombok.Getter;

/**
 * API 统一响应信封：{@code {code, message, data}}。
 *
 * <ul>
 *   <li>成功：{@code code=0}，{@code data} 为业务数据；</li>
 *   <li>失败：{@code code} 为 {@link ErrorCode} 的数字码，{@code data} 恒为 null
 *       （序列化时省略该字段，body 只有 {@code {code, message}}）。</li>
 * </ul>
 *
 * <p>错误响应的 HTTP status 由 {@link ErrorCode#getHttpStatus()} 映射；
 * 无法映射的统一 500。调用方判断业务结果应以 body 的 {@code code} 为准。</p>
 */
@Getter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApiResult<T> {

	private final int code;

	private final String message;

	private final T data;

	private ApiResult(int code, String message, T data) {
		this.code = code;
		this.message = message;
		this.data = data;
	}

	/** 成功响应：{@code {code:0, message:"ok", data:...}}。 */
	public static <T> ApiResult<T> ok(T data) {
		return new ApiResult<>(ErrorCode.SUCCESS.getCode(), ErrorCode.SUCCESS.getDefaultMessage(), data);
	}

	/** 错误响应：{@code {code, message}}，data 序列化时省略。 */
	public static <T> ApiResult<T> error(ErrorCode errorCode, String message) {
		return new ApiResult<>(errorCode.getCode(), message, null);
	}

}
