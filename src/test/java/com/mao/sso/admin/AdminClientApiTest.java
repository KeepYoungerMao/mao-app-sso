package com.mao.sso.admin;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

import com.mao.sso.exception.ErrorCode;
import com.mao.sso.user.UserService;

/**
 * 客户端管理 API 的写入校验（HTTP 层）。
 *
 * <p>服务层的规则由 {@code ClientServiceTest} 覆盖；这里只验证调用方实际收到的
 * HTTP 状态码与错误信封（{@code {code, message}}，data 省略）：</p>
 * <ul>
 *   <li>唯一性冲突（client_id 重复、redirect_uri 被占用）→ <b>409</b> + code 10002；</li>
 *   <li>参数校验失败 → <b>400</b> + code 10000；</li>
 *   <li>绝不返回 500（服务器出错）。</li>
 * </ul>
 */
class AdminClientApiTest extends AdminApiTestSupport {

	private static final String CREATE = "/api/v1/admin/client/create";

	@Test
	@DisplayName("回调地址被其它客户端占用时返回 409 + 业务码 10002，并指出占用者")
	void createRejectsTakenRedirectUriWith409() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		String owner = "occ-owner-" + UUID.randomUUID().toString().substring(0, 8);
		String redirectUri = "http://localhost:9401/" + owner + "/callback";

		this.mockMvc
			.perform(post(CREATE).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content(createBody(owner, redirectUri)))
			.andExpect(status().isOk());

		String thief = "occ-thief-" + UUID.randomUUID().toString().substring(0, 8);
		this.mockMvc
			.perform(post(CREATE).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content(createBody(thief, redirectUri)))
			.andExpect(status().isConflict())
			.andExpect(jsonPath("$.code", is(ErrorCode.DUPLICATE_RESOURCE.getCode())))
			.andExpect(jsonPath("$.message", containsString("已被客户端 " + owner + " 占用")))
			.andExpect(jsonPath("$.data").doesNotExist());
	}

	@Test
	@DisplayName("clientId 重复返回 409 + 业务码 10002（不是 500）")
	void createRejectsDuplicateClientIdWith409() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		String clientId = "dup-" + UUID.randomUUID().toString().substring(0, 8);

		this.mockMvc
			.perform(post(CREATE).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content(createBody(clientId, "http://localhost:9402/" + clientId + "/callback")))
			.andExpect(status().isOk());

		this.mockMvc
			.perform(post(CREATE).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content(createBody(clientId, "http://localhost:9403/" + clientId + "/callback")))
			.andExpect(status().isConflict())
			.andExpect(jsonPath("$.code", is(ErrorCode.DUPLICATE_RESOURCE.getCode())))
			.andExpect(jsonPath("$.message", containsString("client_id 已存在")))
			.andExpect(jsonPath("$.data").doesNotExist());
	}

	@Test
	@DisplayName("回调地址留空返回 400 + 业务码 10000（DTO 校验先于服务层）")
	void createRejectsBlankRedirectUriWith400() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		String clientId = "blank-" + UUID.randomUUID().toString().substring(0, 8);

		this.mockMvc
			.perform(post(CREATE).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content(createBody(clientId, "")))
			.andExpect(status().isBadRequest())
			.andExpect(jsonPath("$.code", is(ErrorCode.INVALID_REQUEST.getCode())))
			.andExpect(jsonPath("$.message", containsString("redirectUri")))
			.andExpect(jsonPath("$.data").doesNotExist());
	}

	@Test
	@DisplayName("分页接口返回信封：records 直接带审计字段，total 与关键词过滤正确")
	void pageReturnsRecordsWithAuditInOneShot() throws Exception {
		String token = accessTokenFor(UserService.ROLE_ADMIN);
		String prefix = "page-" + UUID.randomUUID().toString().substring(0, 8);
		for (int i = 0; i < 2; i++) {
			this.mockMvc
				.perform(post(CREATE).header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
					.contentType(MediaType.APPLICATION_JSON)
					.content(createBody(prefix + "-" + i, "http://localhost:9404/" + prefix + "-" + i + "/cb")))
				.andExpect(status().isOk());
		}

		this.mockMvc
			.perform(post("/api/v1/admin/client/page").header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
				.contentType(MediaType.APPLICATION_JSON)
				.content("{\"pageNum\":1,\"pageSize\":10,\"keyword\":\"%s\"}".formatted(prefix)))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.code", is(0)))
			.andExpect(jsonPath("$.data.total", is(2)))
			.andExpect(jsonPath("$.data.records.length()", is(2)))
			// 审计字段在列表里就能拿到，前端不需要再逐条调详情
			.andExpect(jsonPath("$.data.records[0].clientId", containsString(prefix)))
			.andExpect(jsonPath("$.data.records[0].createdBy").isNotEmpty())
			.andExpect(jsonPath("$.data.records[0].createdAt").isNotEmpty())
			.andExpect(jsonPath("$.data.records[0].updatedBy").isNotEmpty());
	}

	/** 构造创建客户端的 JSON（回调地址为单值）。 */
	private static String createBody(String clientId, String redirectUri) {
		return """
				{"clientId":"%s","clientName":"测试客户端",\
				"authenticationMethods":["none"],"grantTypes":["authorization_code"],\
				"redirectUri":"%s","scopes":["openid"]}
				""".formatted(clientId, redirectUri);
	}

}
