package com.mao.sso.api;

import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import com.mao.sso.api.user.UserService;

/**
 * 管理 API 的授权模型测试：<b>按角色，不按 scope</b>。
 *
 * <p>本服务只定义 openid / profile 两个 scope，且 scope 不参与接口鉴权。
 * 管理接口要求 Access Token 的 {@code roles} claim 含 {@code admin}——该 claim 由
 * {@code JwtClaimsCustomizer} 从用户角色写入，再由
 * {@code ApiSecurityConfig#adminApiJwtAuthenticationConverter} 映射成 {@code ROLE_ADMIN}。</p>
 *
 * <p>覆盖三种情况：管理员 token → 200；普通客户 token → 403；无 token → 401。</p>
 */
class AdminApiAuthorizationTest extends AdminApiTestSupport {

	private static final String API = "/api/v1/admin/user/page";

	@Test
	@DisplayName("管理员（roles 含 admin）可调用管理 API，响应为统一信封 {code,message,data}")
	void adminRoleCanCallAdminApi() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		this.mockMvc
			.perform(post(API).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"pageNum\":1,\"pageSize\":10}"))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.code", is(0)))
			.andExpect(jsonPath("$.message").isString())
			.andExpect(jsonPath("$.data.total").isNumber())
			.andExpect(jsonPath("$.data.records").isArray());
	}

	@Test
	@DisplayName("普通客户（roles 不含 admin）被拒绝：403")
	void customerRoleIsForbidden() throws Exception {
		String token = accessTokenFor(UserService.ROLE_CUSTOMER);
		this.mockMvc
			.perform(post(API).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{}"))
			.andExpect(status().isForbidden());
	}

	@Test
	@DisplayName("无 token 返回 401（管理链不认 Cookie 会话）")
	void anonymousIsUnauthorized() throws Exception {
		this.mockMvc.perform(post(API).contentType(MediaType.APPLICATION_JSON).content("{}"))
			.andExpect(status().isUnauthorized());
	}

}
