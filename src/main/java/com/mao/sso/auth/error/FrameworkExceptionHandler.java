package com.mao.sso.auth.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.method.annotation.HandlerMethodValidationException;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.servlet.resource.NoResourceFoundException;

import jakarta.servlet.http.HttpServletRequest;

import com.mao.sso.domain.error.ApiResult;
import com.mao.sso.domain.error.ErrorCode;
import com.mao.sso.domain.error.RequestKind;
import com.mao.sso.domain.error.RequestKindResolver;

/**
 * 框架层异常的统一兜底（优先级最低，最后检查）。
 *
 * <p>覆盖两类异常：</p>
 * <ul>
 *   <li>Spring 框架的可预期 4xx（无路由、方法不允许、类型不支持、请求体解析失败、
 *       缺少必填参数）—— 这些异常不携带 controller 归属，前两个 advice 不会接管；</li>
 *   <li>一切未分类异常 —— 统一 500，服务端记完整堆栈，响应不泄露内部细节。</li>
 * </ul>
 *
 * <p>呈现形态由 {@link RequestKindResolver} 决定：API 请求返回 {@link ApiResult}
 * 信封，页面请求渲染 4xx/5xx 模板。HTTP status 按 {@link ErrorCode} 映射，
 * 无法映射的统一 500。</p>
 */
@Order(Ordered.LOWEST_PRECEDENCE)
@ControllerAdvice
public class FrameworkExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(FrameworkExceptionHandler.class);

	private final RequestKindResolver requestKindResolver;

	public FrameworkExceptionHandler(RequestKindResolver requestKindResolver) {
		this.requestKindResolver = requestKindResolver;
	}

	@ExceptionHandler(NoResourceFoundException.class)
	public Object handleNoResource(NoResourceFoundException ex, HttpServletRequest request) {
		// 静态资源 404 是正常流量（爬虫、过期链接），不打 error 噪音
		log.debug("资源不存在 uri={}", request.getRequestURI());
		return respond(request, ErrorCode.REQUEST_NOT_FOUND, ErrorCode.REQUEST_NOT_FOUND.getDefaultMessage());
	}

	@ExceptionHandler(HttpRequestMethodNotSupportedException.class)
	public Object handleMethodNotSupported(HttpRequestMethodNotSupportedException ex,
			HttpServletRequest request) {
		log.warn("方法不支持 uri={} method={}", request.getRequestURI(), ex.getMethod());
		return respond(request, ErrorCode.METHOD_NOT_ALLOWED, ErrorCode.METHOD_NOT_ALLOWED.getDefaultMessage());
	}

	@ExceptionHandler(HttpMediaTypeNotSupportedException.class)
	public Object handleMediaTypeNotSupported(HttpMediaTypeNotSupportedException ex,
			HttpServletRequest request) {
		log.warn("内容类型不支持 uri={} contentType={}", request.getRequestURI(), ex.getContentType());
		return respond(request, ErrorCode.UNSUPPORTED_MEDIA_TYPE,
				ErrorCode.UNSUPPORTED_MEDIA_TYPE.getDefaultMessage());
	}

	@ExceptionHandler({ HttpMessageNotReadableException.class, MissingServletRequestParameterException.class,
			MethodArgumentTypeMismatchException.class, HandlerMethodValidationException.class })
	public Object handleBadRequest(Exception ex, HttpServletRequest request) {
		// 参数类型不匹配 / 方法级校验失败属于调用方错误（400），不是服务端故障。
		// 这里刻意不把 ex.getMessage() 回显给调用方：它会带出内部参数名与目标类型。
		log.warn("请求格式错误 uri={} reason={}", request.getRequestURI(), ex.getMessage());
		return respond(request, ErrorCode.INVALID_REQUEST, ErrorCode.INVALID_REQUEST.getDefaultMessage());
	}

	@ExceptionHandler(Exception.class)
	public Object handleUnexpectedException(Exception ex, HttpServletRequest request) {
		// 仅服务端记录完整堆栈，响应中不暴露任何内部细节
		log.error("未处理异常 uri={}", request.getRequestURI(), ex);
		return respond(request, ErrorCode.INTERNAL_ERROR, ErrorCode.INTERNAL_ERROR.getDefaultMessage());
	}

	private Object respond(HttpServletRequest request, ErrorCode errorCode, String message) {
		HttpStatus status = errorCode.getHttpStatus();
		if (this.requestKindResolver.resolve(request) == RequestKind.API) {
			return ResponseEntity.status(status).body(ApiResult.error(errorCode, message));
		}
		return ErrorViews.errorView(status, message);
	}

}
