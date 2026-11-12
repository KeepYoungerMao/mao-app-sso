package com.mao.sso.admin;

import java.util.List;

import jakarta.validation.Valid;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mao.sso.admin.dto.AdminRequests.ClientCreateRequest;
import com.mao.sso.admin.dto.AdminRequests.ClientIdRequest;
import com.mao.sso.admin.dto.AdminRequests.ClientUpdateRequest;
import com.mao.sso.admin.dto.ClientPageRequest;
import com.mao.sso.admin.view.AdminViews.ClientView;
import com.mao.sso.admin.view.AdminViews.CreatedClientView;
import com.mao.sso.admin.view.AdminViews.DeletedView;
import com.mao.sso.common.page.PageResult;
import com.mao.sso.oauth.ClientService;

/**
 * 客户端管理 API。
 *
 * <p>所有客户端统一存储在 {@code oauth2_registered_client}（Spring Authorization Server 官方 schema），
 * 与 DCR 端点共用同一份数据：管理 API 负责录入与维护，DCR 负责按 redirect_uri 查表返回固定 client_id。</p>
 */
@RestController
@RequestMapping(path = "/api/v1/admin/client", produces = MediaType.APPLICATION_JSON_VALUE)
public class AdminClientController {

	private final ClientService clientService;

	public AdminClientController(ClientService clientService) {
		this.clientService = clientService;
	}

	/** 客户端分页查询。 */
	@PostMapping("/page")
	public PageResult<ClientView> page(@RequestBody(required = false) ClientPageRequest request) {
		ClientPageRequest query = (request != null) ? request : new ClientPageRequest();
		PageResult<ClientService.ClientDetail> page = this.clientService.pageClients(query, query.getKeyword());
		// 分页记录已带审计字段，无需逐条 requireDetail（那是 3N 次查询）
		List<ClientView> records = page.getRecords().stream().map(ClientView::from).toList();
		return new PageResult<>(page.getPageNum(), page.getPageSize(), page.getTotal(), records);
	}

	/** 客户端详情（含审计字段）。 */
	@PostMapping("/detail")
	public ClientView detail(@Valid @RequestBody ClientIdRequest request) {
		return ClientView.from(this.clientService.requireDetail(request.clientId()));
	}

	/** 创建客户端：机密客户端的明文密钥在响应中一次性返回。 */
	@PostMapping("/create")
	public CreatedClientView create(@Valid @RequestBody ClientCreateRequest request) {
		ClientService.CreatedClient created = this.clientService.createClient(request.clientId(),
				request.clientName(), request.clientSecret(), request.authenticationMethods(),
				request.grantTypes(), request.redirectUri(), request.scopes(),
				(resolve(request.requireConsent(), true)), resolve(request.requireProofKey(), true));
		return new CreatedClientView(created.clientId(), created.clientSecret());
	}

	/** 更新客户端可变属性。 */
	@PostMapping("/update")
	public ClientView update(@Valid @RequestBody ClientUpdateRequest request) {
		this.clientService.updateClient(request.clientId(), request.clientName(), request.redirectUri(),
				request.scopes(), request.requireConsent(), request.requireProofKey());
		return ClientView.from(this.clientService.requireDetail(request.clientId()));
	}

	/** 删除客户端（管理控制台自身客户端受保护）。 */
	@PostMapping("/delete")
	public DeletedView delete(@Valid @RequestBody ClientIdRequest request) {
		this.clientService.deleteClient(request.clientId());
		return new DeletedView(null, true);
	}

	private static boolean resolve(Boolean value, boolean defaultValue) {
		return (value != null) ? value : defaultValue;
	}

}
