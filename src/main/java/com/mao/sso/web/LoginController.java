package com.mao.sso.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.util.StringUtils;
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

	/**
	 * 登录页。
	 *
	 * <p>{@code error} / {@code logout} 刻意声明为 {@link String} 而非 {@code boolean}：
	 * 这两个标记只表示「出现过该事件」，具体值无意义。若声明为 {@code boolean}，
	 * 外部拼一个 {@code /login?error}（空值）就会被 Spring 判为
	 * {@code Invalid boolean value []}，把本该正常渲染的登录页打成 500。</p>
	 */
	@GetMapping("/login")
	public ModelAndView loginPage(@AuthenticationPrincipal User principal,
			@RequestParam(value = "error", required = false) String error,
			@RequestParam(value = "logout", required = false) String logout,
			HttpServletRequest request, HttpServletResponse response) {
		if (principal != null) {
			return new ModelAndView("redirect:/");
		}
		ModelAndView mav = new ModelAndView("login");
		if (StringUtils.hasText(error)) {
			mav.addObject("errorMessage", "用户名或密码错误，请重试");
		}
		if (StringUtils.hasText(logout)) {
			mav.addObject("logoutMessage", "您已安全退出登录");
		}
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (savedRequest != null) {
			mav.addObject("pendingAuthorization", true);
		}
		return mav;
	}

}
