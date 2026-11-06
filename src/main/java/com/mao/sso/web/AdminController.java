package com.mao.sso.web;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.mao.sso.user.UserService;

/**
 * 管理页（仅 ROLE_ADMIN 可访问，用于演示基于角色的访问控制）：
 * 用户列表、启用/禁用、锁定/解锁。
 */
@Controller
public class AdminController {

	private final UserService userService;

	public AdminController(UserService userService) {
		this.userService = userService;
	}

	@GetMapping("/admin/users")
	public ModelAndView userList(@AuthenticationPrincipal User principal) {
		var currentUser = this.userService.requireUser(principal.getUsername());
		ModelAndView mav = new ModelAndView("admin-users");
		mav.addObject("users", this.userService.findAllUsers());
		mav.addObject("currentUserId", currentUser.getId());
		return mav;
	}

	@PostMapping("/admin/users/status")
	public ModelAndView updateStatus(@RequestParam("userId") Long userId,
			@RequestParam("enabled") boolean enabled, @RequestParam("locked") boolean locked,
			RedirectAttributes redirectAttributes) {
		this.userService.updateStatus(userId, enabled, locked);
		redirectAttributes.addFlashAttribute("successMessage", "用户状态已更新");
		return new ModelAndView("redirect:/admin/users");
	}

}
