package com.mao.sso.exception;

/** 唯一约束冲突（重复用户名、邮箱等）。 */
public class DuplicateResourceException extends BusinessException {

	public DuplicateResourceException(String userMessage) {
		super(userMessage);
	}

}
