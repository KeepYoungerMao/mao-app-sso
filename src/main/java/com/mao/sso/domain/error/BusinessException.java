package com.mao.sso.domain.error;

import lombok.Getter;

/**
 * 业务异常基类：message 面向终端用户，可安全展示。
 *
 * <p>每个业务异常必须携带 {@link ErrorCode} —— 它同时决定 API 响应 body 中的
 * 数字码与 HTTP status（页面请求则映射到对应的 4xx/5xx 模板）。</p>
 */
@Getter
public abstract class BusinessException extends RuntimeException {

	private final ErrorCode errorCode;

	private final String userMessage;

	protected BusinessException(ErrorCode errorCode, String userMessage) {
		super(userMessage);
		this.errorCode = errorCode;
		this.userMessage = userMessage;
	}

	protected BusinessException(ErrorCode errorCode, String userMessage, Throwable cause) {
		super(userMessage, cause);
		this.errorCode = errorCode;
		this.userMessage = userMessage;
	}

}
