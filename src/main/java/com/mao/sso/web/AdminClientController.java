package com.mao.sso.web;

import java.util.Arrays;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.mao.sso.oauth.ClientService;

/**
 * 客户端管理页（仅 ROLE_ADMIN 可访问）：
 * 客户端列表、新建客户端、删除客户端、重新生成密钥。
 *
 * <p>所有客户端（无论 AI 连接器、前端应用、后端服务）统一在此管理。
 * 预录入的客户端自动支持 DCR 动态注册（按 redirect_uri 查表返回固定 client_id）。</p>
 */
@Controller
public class AdminClientController {

	private static final Logger log = LoggerFactory.getLogger(AdminClientController.class);

	private final ClientService clientService;

	public AdminClientController(ClientService clientService) {
		this.clientService = clientService;
	}

	@GetMapping("/admin/clients")
	public ModelAndView clientList() {
		ModelAndView mav = new ModelAndView("admin-clients");
		mav.addObject("clients", clientService.listClients());
		return mav;
	}

	@PostMapping("/admin/clients")
	public ModelAndView createClient(
			@RequestParam("clientId") String clientId,
			@RequestParam("clientName") String clientName,
			@RequestParam(value = "clientSecret", defaultValue = "") String clientSecret,
			@RequestParam(value = "authMethods", defaultValue = "none") String authMethods,
			@RequestParam(value = "grantTypes", defaultValue = "authorization_code,refresh_token") String grantTypes,
			@RequestParam("redirectUris") String redirectUris,
			@RequestParam(value = "scopes", defaultValue = "openid,profile,email") String scopes,
			@RequestParam(value = "requireConsent", defaultValue = "true") boolean requireConsent,
			@RequestParam(value = "requireProofKey", defaultValue = "true") boolean requireProofKey,
			RedirectAttributes redirectAttributes) {
		try {
			clientService.createClient(
				clientId.trim(),
				clientName.trim(),
				clientSecret,
				splitAndTrim(authMethods),
				splitAndTrim(grantTypes),
				splitAndTrim(redirectUris),
				splitAndTrim(scopes),
				requireConsent,
				requireProofKey);
			redirectAttributes.addFlashAttribute("successMessage", "客户端 " + clientId + " 已创建");
		}
		catch (Exception e) {
			redirectAttributes.addFlashAttribute("errorMessage", "创建失败: " + e.getMessage());
			log.error("创建客户端失败: clientId={}", clientId, e);
		}
		return new ModelAndView("redirect:/admin/clients");
	}

	@PostMapping("/admin/clients/regenerate-secret")
	public ModelAndView regenerateSecret(@RequestParam("clientId") String clientId,
			RedirectAttributes redirectAttributes) {
		try {
			String newSecret = clientService.regenerateSecret(clientId);
			redirectAttributes.addFlashAttribute("successMessage",
					"客户端 " + clientId + " 的新密钥: " + newSecret + "（请立即复制，关闭后不可找回）");
		}
		catch (Exception e) {
			redirectAttributes.addFlashAttribute("errorMessage", "密钥生成失败: " + e.getMessage());
			log.error("重新生成密钥失败: clientId={}", clientId, e);
		}
		return new ModelAndView("redirect:/admin/clients");
	}

	@PostMapping("/admin/clients/delete")
	public ModelAndView deleteClient(@RequestParam("clientId") String clientId,
			RedirectAttributes redirectAttributes) {
		try {
			clientService.deleteClient(clientId);
			redirectAttributes.addFlashAttribute("successMessage", "客户端 " + clientId + " 已删除");
		}
		catch (Exception e) {
			redirectAttributes.addFlashAttribute("errorMessage", "删除失败: " + e.getMessage());
			log.error("删除客户端失败: clientId={}", clientId, e);
		}
		return new ModelAndView("redirect:/admin/clients");
	}

	// ---------- 工具 ----------

	private static List<String> splitAndTrim(String input) {
		if (!StringUtils.hasText(input)) {
			return List.of();
		}
		return Arrays.stream(input.split("[,;，；\\s]+"))
			.map(String::trim)
			.filter(StringUtils::hasText)
			.toList();
	}

}