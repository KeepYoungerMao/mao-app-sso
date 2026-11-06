package com.mao.sso.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import com.mao.sso.user.UserService;

/**
 * 首页：展示当前登录用户信息与角色（游客可见登录入口）。
 */
@Controller
public class HomeController {

	private final UserService userService;

	public HomeController(UserService userService) {
		this.userService = userService;
	}

	@GetMapping("/")
	public ModelAndView home(@AuthenticationPrincipal User principal) {
		ModelAndView mav = new ModelAndView("home");
		mav.addObject("principal", principal);
		if (principal != null) {
			mav.addObject("profile", this.userService.requireUser(principal.getUsername()));
		}
		return mav;
	}

}
