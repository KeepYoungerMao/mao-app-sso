package com.mao.sso.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import jakarta.servlet.http.HttpServletRequest;

/**
 * REST 控制器（管理 API）的业务异常处理：输出 {@link ApiResult} 信封。
 *
 * <p>仅匹配 {@code @RestController} 标注的控制器，按 {@link Order} 最先检查。
 * 只声明有明确业务语义的异常：</p>
 * <ul>
 *   <li>{@link BusinessException} → HTTP status 取 {@link ErrorCode} 映射，body 带业务码；</li>
 *   <li>{@link MethodArgumentNotValidException} → 400 + 字段错误明细。</li>
 * </ul>
 *
 * <p>刻意不声明 {@code Exception.class} 兜底：REST 控制器的其余异常（含框架 4xx
 * 如 JSON 解析失败）统一落到 {@link FrameworkExceptionHandler} 按映射处理，
 * 避免在这里被吞成 500。</p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE)
@RestControllerAdvice(annotations = RestController.class)
public class ApiExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(ApiExceptionHandler.class);

	@ExceptionHandler(BusinessException.class)
	public ResponseEntity<ApiResult<Void>> handleBusinessException(BusinessException ex,
			HttpServletRequest request) {
		ErrorCode errorCode = ex.getErrorCode();
		log.warn("API 业务异常 uri={} code={} message={}", request.getRequestURI(), errorCode.getCode(),
				ex.getUserMessage());
		return ResponseEntity.status(errorCode.getHttpStatus())
			.body(ApiResult.error(errorCode, ex.getUserMessage()));
	}

	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<ApiResult<Void>> handleValidationException(MethodArgumentNotValidException ex,
			HttpServletRequest request) {
		String message = ex.getBindingResult()
			.getFieldErrors()
			.stream()
			.map((error) -> error.getField() + ": " + error.getDefaultMessage())
			.reduce((first, second) -> first + "; " + second)
			.orElse(ErrorCode.INVALID_REQUEST.getDefaultMessage());
		log.warn("API 参数校验失败 uri={} errors={}", request.getRequestURI(), message);
		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
			.body(ApiResult.error(ErrorCode.INVALID_REQUEST, message));
	}

}
