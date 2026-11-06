package com.mao.sso.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

/**
 * 登出结果页（安全退出确认）。
 */
@Controller
public class LogoutSuccessController {

	@GetMapping("/logout-success")
	public ModelAndView logoutSuccessPage() {
		return new ModelAndView("logout-success");
	}

}
