package com.mao.sso.domain.error;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;

/**
 * 在 Spring Security 过滤器链内写出统一的 JSON 错误信封。
 *
 * <p>为什么单独成一个类：三条 {@code SecurityFilterChain}（认证服务器 / 管理 API / 门户）
 * 与 {@code FrameworkExceptionHandler} 都需要“把 401/403 渲染成 {@link ApiResult}”，
 * 抽出来避免三个配置文件各抄一份。</p>
 *
 * <p>注意：管理 API 链的 401/403 刻意<b>不走</b>这里，而是交给 Spring Security 默认的
 * RFC 6750 {@code BearerToken} 实现 —— OAuth 生态（MCP / CLI 客户端）依赖那个格式。</p>
 */
@Component
public class JsonErrorWriter {

	private final ObjectMapper objectMapper;

	public JsonErrorWriter(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	/**
	 * 写出错误信封：{@code {"code":1xxxx,"message":"..."}}。
	 *
	 * @param status HTTP 状态码
	 * @param errorCode 业务错误码（同时提供默认文案）
	 */
	public void write(HttpServletResponse response, HttpStatus status, ErrorCode errorCode) throws IOException {
		response.setStatus(status.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		this.objectMapper.writeValue(response.getWriter(),
				ApiResult.error(errorCode, errorCode.getDefaultMessage()));
	}

}
