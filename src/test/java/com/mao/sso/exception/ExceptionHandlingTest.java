package com.mao.sso.exception;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import jakarta.servlet.RequestDispatcher;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import com.mao.sso.admin.AdminApiTestSupport;
import com.mao.sso.user.UserService;

/**
 * 统一异常处理的端到端测试：验证「判定 → 映射 → 呈现」三层约定。
 *
 * <ul>
 *   <li>API 请求（/api/**）：成功包 {@code {code:0,message,data}} 信封，
 *       错误返回 {@code {code,message}}，HTTP status 按 {@link ErrorCode} 映射；</li>
 *   <li>页面请求：错误渲染 error/4xx、error/5xx 模板；</li>
 *   <li>Web 链认证分流：HTML 未认证 → 302 /login，非 HTML 未认证 → 401 JSON。</li>
 * </ul>
 */
class ExceptionHandlingTest extends AdminApiTestSupport {

	// ---------- API：成功信封 ----------

	@Test
	@DisplayName("API 成功响应统一包装为 {code:0, message, data} 信封")
	void apiSuccessResponseIsWrapped() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		this.mockMvc
			.perform(post("/api/v1/admin/user/page").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"pageNum\":1,\"pageSize\":10}"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.code", is(0)))
			.andExpect(jsonPath("$.data.total").isNumber())
			.andExpect(jsonPath("$.data.records").isArray());
	}

	// ---------- API：错误信封 + 状态码映射 ----------

	@Test
	@DisplayName("API 资源不存在 → 404 + code 10001（映射到 NOT_FOUND，不再是 400/500）")
	void apiResourceNotFoundReturns404() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		this.mockMvc
			.perform(post("/api/v1/admin/client/detail").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"clientId\":\"no-such-client\"}"))
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.code", is(ErrorCode.RESOURCE_NOT_FOUND.getCode())))
			.andExpect(jsonPath("$.message", containsString("客户端不存在")))
			.andExpect(jsonPath("$.data").doesNotExist());
	}

	@Test
	@DisplayName("API 请求体 JSON 格式错误 → 400 + code 10000（不再被吞成 500）")
	void apiMalformedJsonReturns400() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		this.mockMvc
			.perform(post("/api/v1/admin/client/create").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{not-a-json"))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code", is(ErrorCode.INVALID_REQUEST.getCode())))
			.andExpect(jsonPath("$.data").doesNotExist());
	}

	@Test
	@DisplayName("API 未知路径 → 404 + code 10404（框架 404 不再被吞成 500）")
	void apiUnknownPathReturns404Json() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		this.mockMvc
			.perform(post("/api/v1/admin/no-such-endpoint").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{}"))
			.andExpect(status().isNotFound())
			.andExpect(jsonPath("$.code", is(ErrorCode.REQUEST_NOT_FOUND.getCode())))
			.andExpect(jsonPath("$.data").doesNotExist());
	}

	// ---------- 页面：错误模板 ----------

	@Test
	@DisplayName("容器 sendError 转发（模型无 errorMessage）→ 403 仍渲染 error/4xx，不显示通用告警")
	void sendErrorDispatchRenders4xx() throws Exception {
		// 模拟 response.sendError(403) 之后的 ERROR 转发：模型里只有 status/error/path
		this.mockMvc
			.perform(get("/error").accept(MediaType.TEXT_HTML)
				.requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 403)
				.requestAttr(RequestDispatcher.ERROR_REQUEST_URI, "/profile"))
			.andExpect(status().isForbidden())
			.andExpect(view().name("error/4xx"))
			.andExpect(content().string(containsString("没有访问权限")))
			.andExpect(content().string(containsString("当前账号没有访问该资源的权限")))
			.andExpect(content().string(not(containsString("alert alert-error"))));
	}

	@Test
	@DisplayName("容器 sendError(500) 转发 → error/5xx，且不泄露异常细节")
	void sendErrorDispatchRenders5xx() throws Exception {
		this.mockMvc
			.perform(get("/error").accept(MediaType.TEXT_HTML)
				.requestAttr(RequestDispatcher.ERROR_STATUS_CODE, 500)
				.requestAttr(RequestDispatcher.ERROR_EXCEPTION, new IllegalStateException("boom-secret")))
			.andExpect(status().isInternalServerError())
			.andExpect(view().name("error/5xx"))
			.andExpect(content().string(containsString("服务器开小差了")))
			.andExpect(content().string(not(containsString("boom-secret"))));
	}

	@Test
	@DisplayName("页面请求未知路径 → 404 渲染 error/4xx 模板，标题给状态人话")
	void pageNotFoundRenders4xxTemplate() throws Exception {
		this.mockMvc
			.perform(get("/no-such-page").accept(MediaType.TEXT_HTML).with(user("tester").roles("CUSTOMER")))
			.andExpect(status().isNotFound())
			.andExpect(view().name("error/4xx"))
			.andExpect(content().string(containsString("页面不存在")))
			.andExpect(content().string(containsString("请求的地址不存在")));
	}

	@Test
	@DisplayName("页面控制器抛业务异常 → 按 ErrorCode 状态码渲染对应模板")
	void pageBusinessExceptionRenders4xxTemplate() throws Exception {
		// consent 页收到未知 client_id 抛 InvalidRequestException → 400 + error/4xx
		this.mockMvc
			.perform(get("/oauth2/consent").param("client_id", "no-such-client")
				.param("scope", "openid")
				.param("state", "x")
				.accept(MediaType.TEXT_HTML)
				.with(user("tester").roles("CUSTOMER")))
			.andExpect(status().isBadRequest())
			.andExpect(view().name("error/4xx"))
			.andExpect(content().string(containsString("请求参数有误")));
	}

	// ---------- Web 链：认证分流 ----------

	@Test
	@DisplayName("非 HTML 请求未认证 → 401 JSON 信封（不再是 403 空响应）")
	void anonymousApiRequestReturns401Json() throws Exception {
		this.mockMvc
			.perform(get("/profile").accept(MediaType.APPLICATION_JSON))
			.andExpect(status().isUnauthorized())
			.andExpect(jsonPath("$.code", is(ErrorCode.UNAUTHORIZED.getCode())))
			.andExpect(jsonPath("$.data").doesNotExist());
	}

	@Test
	@DisplayName("HTML 请求未认证 → 302 登录页（既有行为保持）")
	void anonymousPageRequestRedirectsToLogin() throws Exception {
		this.mockMvc
			.perform(get("/profile").accept(MediaType.TEXT_HTML))
			.andExpect(status().is3xxRedirection())
			.andExpect(redirectedUrl("/login"));
	}

}
