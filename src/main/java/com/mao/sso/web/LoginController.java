package com.mao.sso.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * 登录页控制器。
 *
 * <p>已登录用户访问 /login 直接跳转首页；OAuth 授权流程中登录成功后
 * 由 {@link com.mao.sso.security.LoginSuccessHandler} 跳回保存的授权请求。</p>
 */
@Controller
public class LoginController {

	private final RequestCache requestCache = new HttpSessionRequestCache();

	@GetMapping("/login")
	public ModelAndView loginPage(@AuthenticationPrincipal User principal,
			@RequestParam(value = "error", required = false) boolean error,
			@RequestParam(value = "logout", required = false) boolean logout,
			HttpServletRequest request, HttpServletResponse response) {
		if (principal != null) {
			return new ModelAndView("redirect:/");
		}
		ModelAndView mav = new ModelAndView("login");
		if (error) {
			mav.addObject("errorMessage", "用户名或密码错误，请重试");
		}
		if (logout) {
			mav.addObject("logoutMessage", "您已安全退出登录");
		}
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (savedRequest != null) {
			mav.addObject("pendingAuthorization", true);
		}
		return mav;
	}

}
