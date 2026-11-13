package com.mao.sso.domain.error;

/**
 * 唯一约束冲突（重复用户名、邮箱、client_id、redirect_uri 等）→ HTTP 409，code 10002。
 */
public class DuplicateResourceException extends BusinessException {

	public DuplicateResourceException(String userMessage) {
		super(ErrorCode.DUPLICATE_RESOURCE, userMessage);
	}

}
