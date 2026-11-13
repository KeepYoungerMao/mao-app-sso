package com.mao.sso.auth.error;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;

import com.mao.sso.domain.error.BusinessException;
import com.mao.sso.domain.error.ErrorCode;

/**
 * 页面控制器的业务异常处理：渲染 4xx/5xx 错误模板。
 *
 * <p>刻意不声明 {@code Exception.class} 兜底：{@code @RestController} 通过元注解
 * 同样匹配本 advice，若声明兜底会抢走 REST 控制器的未知异常并渲染成错误页。
 * 所有控制器的未知异常统一由 {@link FrameworkExceptionHandler} 兜底。</p>
 *
 * <p>页面控制器的表单校验走 {@code BindingResult}，不会以异常形式到达这里；
 * 本处理器主要覆盖 {@code AuthorizationConsentController} 等场景抛出的业务异常。</p>
 */
@Order(Ordered.HIGHEST_PRECEDENCE + 10)
@ControllerAdvice(annotations = Controller.class)
public class PageExceptionHandler {

	private static final Logger log = LoggerFactory.getLogger(PageExceptionHandler.class);

	@ExceptionHandler(BusinessException.class)
	public ModelAndView handleBusinessException(BusinessException ex, HttpServletRequest request) {
		ErrorCode errorCode = ex.getErrorCode();
		log.warn("页面业务异常 uri={} code={} message={}", request.getRequestURI(), errorCode.getCode(),
				ex.getUserMessage());
		return ErrorViews.errorView(errorCode.getHttpStatus(), ex.getUserMessage());
	}

}
