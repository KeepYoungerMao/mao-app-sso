package com.mao.sso.exception;

/**
 * 业务异常基类：message 面向终端用户，可安全展示。
 */
public abstract class BusinessException extends RuntimeException {

	private final String userMessage;

	protected BusinessException(String userMessage) {
		super(userMessage);
		this.userMessage = userMessage;
	}

	protected BusinessException(String userMessage, Throwable cause) {
		super(userMessage, cause);
		this.userMessage = userMessage;
	}

	public String getUserMessage() {
		return this.userMessage;
	}

}
