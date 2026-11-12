package com.mao.sso.exception;

import org.jspecify.annotations.NonNull;
import org.springframework.core.MethodParameter;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * 成功响应统一包装为 {@link ApiResult} 信封（{@code {code:0, message:"ok", data}}）。
 *
 * <p>仅作用于 {@code @RestController} 标注的控制器；控制器方法保持返回裸业务对象，
 * 由本类在写响应前统一加壳，避免每个端点手写 {@code ApiResult.ok(...)}。</p>
 *
 * <p>跳过两种情况：返回值本身已是 {@link ApiResult}（错误响应由 advice 构造），
 * 以及 {@code String} 返回值（会被 Jackson 二次序列化为带引号的 JSON 字符串）。</p>
 */
@RestControllerAdvice(annotations = RestController.class)
public class ApiResultWrapper implements ResponseBodyAdvice<Object> {

	@Override
	public boolean supports(MethodParameter returnType, @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
		return !ApiResult.class.isAssignableFrom(returnType.getParameterType())
				&& !CharSequence.class.isAssignableFrom(returnType.getParameterType());
	}

	@Override
	public Object beforeBodyWrite(Object body,
								  @NonNull MethodParameter returnType,
								  @NonNull MediaType selectedContentType,
                                  @NonNull Class<? extends HttpMessageConverter<?>> selectedConverterType,
								  @NonNull ServerHttpRequest request,
                                  @NonNull ServerHttpResponse response) {
		if (body instanceof ApiResult) {
			return body;
		}
		return ApiResult.ok(body);
	}

}
