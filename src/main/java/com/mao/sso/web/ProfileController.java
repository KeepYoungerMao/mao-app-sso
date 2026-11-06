package com.mao.sso.web;

import jakarta.validation.Valid;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.mao.sso.user.UserService;

/**
 * 个人资料页：展示账户状态、角色，并提供显示名称修改表单
 * （用于演示表单校验错误展示与 CSRF 保护表单）。
 */
@Controller
public class ProfileController {

	private final UserService userService;

	public ProfileController(UserService userService) {
		this.userService = userService;
	}

	@GetMapping("/profile")
	public ModelAndView profilePage(@AuthenticationPrincipal User principal) {
		ModelAndView mav = new ModelAndView("profile");
		mav.addObject("user", this.userService.requireUser(principal.getUsername()));
		mav.addObject("profileForm", new ProfileForm());
		return mav;
	}

	@PostMapping("/profile")
	public ModelAndView updateProfile(@AuthenticationPrincipal User principal,
			@Valid @ModelAttribute("profileForm") ProfileForm profileForm, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		var user = this.userService.requireUser(principal.getUsername());
		if (bindingResult.hasErrors()) {
			ModelAndView mav = new ModelAndView("profile");
			mav.addObject("user", user);
			return mav;
		}
		this.userService.updateDisplayName(user.getId(), profileForm.getDisplayName().trim());
		redirectAttributes.addFlashAttribute("successMessage", "显示名称已更新");
		return new ModelAndView("redirect:/profile");
	}

}
