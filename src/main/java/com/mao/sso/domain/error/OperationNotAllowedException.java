package com.mao.sso.domain.error;

/**
 * 操作不被允许（如删除系统最后一个管理员、删除管理控制台自身客户端）
 * → HTTP 409，code 10003。
 */
public class OperationNotAllowedException extends BusinessException {

	public OperationNotAllowedException(String userMessage) {
		super(ErrorCode.OPERATION_NOT_ALLOWED, userMessage);
	}

}
