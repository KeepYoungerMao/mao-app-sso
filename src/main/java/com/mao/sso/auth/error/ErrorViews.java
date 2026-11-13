package com.mao.sso.auth.error;

import org.springframework.http.HttpStatus;
import org.springframework.web.servlet.ModelAndView;

/**
 * 错误页视图构造工具：按状态码选择 {@code error/4xx} 或 {@code error/5xx} 模板。
 *
 * <p>与 {@code BasicErrorController} 的默认视图解析（templates/error/{status}.html、
 * templates/error/4xx.html、templates/error/5xx.html）使用同一组模板，
 * 保证「advice 主动渲染」与「容器 sendError 转发」两种路径的用户体验一致。</p>
 */
final class ErrorViews {

	private ErrorViews() {
	}

	static ModelAndView errorView(HttpStatus status, String message) {
		ModelAndView mav = new ModelAndView(status.is5xxServerError() ? "error/5xx" : "error/4xx");
		mav.setStatus(status);
		mav.addObject("status", status.value());
		mav.addObject("errorMessage", message);
		return mav;
	}

}
