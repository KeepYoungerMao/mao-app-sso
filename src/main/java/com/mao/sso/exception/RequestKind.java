package com.mao.sso.exception;

/**
 * 请求形态：决定错误以 JSON 信封还是错误页呈现。
 *
 * @see RequestKindResolver
 */
public enum RequestKind {

	/** API 调用：返回 {@link ApiResult} JSON 信封。 */
	API,

	/** 页面访问：渲染错误模板（templates/error/）。 */
	PAGE

}
