package com.mao.sso.exception;

/**
 * 资源不存在 → HTTP 404，code 10001。
 */
public class ResourceNotFoundException extends BusinessException {

	public ResourceNotFoundException(String userMessage) {
		super(ErrorCode.RESOURCE_NOT_FOUND, userMessage);
	}

}
