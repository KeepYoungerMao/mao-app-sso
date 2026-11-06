package com.mao.sso.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.http.HttpServletRequest;

/**
 * 统一异常处理。
 *
 * <ul>
 *   <li>REST 接口：返回 RFC 7807 ProblemDetail，不泄露堆栈与内部细节；</li>
 *   <li>页面请求：渲染统一错误页（templates/error.html）。</li>
 * </ul>
 *
 * <p>注意：OAuth 端点（/oauth2/**、/userinfo）由 Spring Authorization Server 自行处理，
 * 不经过本处理器，其错误响应遵循 OAuth 2.1 规范。</p>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

	@ExceptionHandler(BusinessException.class)
	public Object handleBusinessException(BusinessException ex, HttpServletRequest request) {
		log.warn("业务异常 uri={} message={}", request.getRequestURI(), ex.getUserMessage());
		if (isRestRequest(request)) {
			return problemDetail(HttpStatus.BAD_REQUEST, "业务错误", ex.getUserMessage());
		}
		return pageView(HttpStatus.BAD_REQUEST, ex.getUserMessage());
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public Object handleValidationException(MethodArgumentNotValidException ex, HttpServletRequest request) {
		String message = ex.getBindingResult().getFieldErrors().stream()
			.map((error) -> error.getField() + ": " + error.getDefaultMessage())
			.reduce((first, second) -> first + "; " + second)
			.orElse("请求参数校验失败");
		log.warn("参数校验失败 uri={} errors={}", request.getRequestURI(), message);
		if (isRestRequest(request)) {
			return problemDetail(HttpStatus.BAD_REQUEST, "参数校验失败", message);
		}
		return pageView(HttpStatus.BAD_REQUEST, message);
	}

	@ExceptionHandler(Exception.class)
	public Object handleUnexpectedException(Exception ex, HttpServletRequest request) {
		// 仅服务端记录完整堆栈，响应中不暴露任何内部细节
		log.error("未处理异常 uri={}", request.getRequestURI(), ex);
		HttpStatus status = resolveStatus(request);
		if (isRestRequest(request)) {
			return problemDetail(status, "服务器内部错误", "服务器内部错误，请稍后重试");
		}
		return pageView(status, "服务器内部错误，请稍后重试或联系管理员");
	}

	private static HttpStatus resolveStatus(HttpServletRequest request) {
		Object status = request.getAttribute(RequestDispatcher.ERROR_STATUS_CODE);
		if (status instanceof Integer code && code >= 400 && code <= 599) {
			return HttpStatus.valueOf(code);
		}
		return HttpStatus.INTERNAL_SERVER_ERROR;
	}

	private static boolean isRestRequest(HttpServletRequest request) {
		String uri = request.getRequestURI();
		String accept = request.getHeader("Accept");
		return uri.startsWith("/api/") || (accept != null && accept.contains("application/json"));
	}

	private static ProblemDetail problemDetail(HttpStatus status, String title, String detail) {
		ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
		problem.setTitle(title);
		return problem;
	}

	private static ModelAndView pageView(HttpStatus status, String message) {
		ModelAndView mav = new ModelAndView("error");
		mav.setStatus(status);
		mav.addObject("errorMessage", message);
		return mav;
	}

}
