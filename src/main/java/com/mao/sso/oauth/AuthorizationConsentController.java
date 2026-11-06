package com.mao.sso.oauth;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

/**
 * 授权确认页（Consent Page）。
 *
 * <p>由 {@code OAuth2AuthorizationEndpointConfigurer.consentPage("/oauth2/consent")} 指定：
 * 用户在授权码流程中首次授权某客户端时被重定向到此页面。</p>
 *
 * <p>表单必须以 POST 提交到授权端点（/oauth2/authorize），并携带 client_id、state
 * 与被授权的 scope 列表（scope 为空表示拒绝授权，客户端将收到 error=access_denied）。</p>
 *
 * <p>注意：本页面不属于授权服务器端点，由普通 Web 安全链保护（需已登录）；
 * POST 授权端点由 state 参数提供 CSRF 防护（RFC 6749 要求）。</p>
 */
@Controller
public class AuthorizationConsentController {

	private static final Map<String, String> SCOPE_DESCRIPTIONS = Map.of("openid", "登录并识别您的身份（OpenID Connect）",
			"profile", "查看您的基本资料（显示名称等）", "email", "查看您的电子邮箱地址");

	private final RegisteredClientRepository registeredClientRepository;

	public AuthorizationConsentController(RegisteredClientRepository registeredClientRepository) {
		this.registeredClientRepository = registeredClientRepository;
	}

	@GetMapping("/oauth2/consent")
	public ModelAndView consent(@RequestParam("client_id") String clientId,
			@RequestParam("scope") String scope, @RequestParam("state") String state) {
		RegisteredClient client = this.registeredClientRepository.findByClientId(clientId);
		if (client == null) {
			throw new IllegalArgumentException("未知的客户端: " + clientId);
		}
		List<Map<String, String>> scopes = List.of(scope.split(" "))
			.stream()
			.filter((s) -> !s.isBlank())
			.distinct()
			.sorted()
			.map((s) -> Map.of("code", s, "description", SCOPE_DESCRIPTIONS.getOrDefault(s, s)))
			.toList();
		ModelAndView mav = new ModelAndView("consent");
		mav.addObject("clientId", clientId);
		mav.addObject("clientName", client.getClientName());
		mav.addObject("state", state);
		mav.addObject("scopes", scopes);
		return mav;
	}

}
