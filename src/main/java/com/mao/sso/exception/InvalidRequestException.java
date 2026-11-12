package com.mao.sso.exception;

/**
 * 请求参数不合法（可预期的业务校验失败）→ HTTP 400，code 10000。
 *
 * <p>与 {@link IllegalArgumentException} 的区别：本异常继承 {@link BusinessException}，
 * 会被映射为 <b>400</b> 并把 message 原样返回给调用方；
 * 而裸的 {@link IllegalArgumentException} 会落到兜底的 {@code Exception} 处理器变成 500，
 * 让「参数填错」看起来像「服务器出错」。服务层校验失败一律抛本异常。</p>
 */
public class InvalidRequestException extends BusinessException {

	public InvalidRequestException(String userMessage) {
		super(ErrorCode.INVALID_REQUEST, userMessage);
	}

	public InvalidRequestException(String userMessage, Throwable cause) {
		super(ErrorCode.INVALID_REQUEST, userMessage, cause);
	}

}
