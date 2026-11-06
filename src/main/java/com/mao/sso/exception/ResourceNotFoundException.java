package com.mao.sso.exception;

/** 资源不存在。 */
public class ResourceNotFoundException extends BusinessException {

	public ResourceNotFoundException(String userMessage) {
		super(userMessage);
	}

}
