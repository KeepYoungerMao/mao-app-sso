package com.mao.sso.web;

import jakarta.validation.Valid;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.mao.sso.user.UserService;

/**
 * 个人资料页：展示账户状态、角色，提供显示名称修改与自助改密。
 *
 * <p>自助改密是 {@code must_change_password} 标记的唯一清除路径：
 * 管理员创建用户/重置密码后该标记为 true，用户在此完成改密后归零。</p>
 */
@Controller
public class ProfileController {

	private final UserService userService;

	private final PasswordEncoder passwordEncoder;

	public ProfileController(UserService userService, PasswordEncoder passwordEncoder) {
		this.userService = userService;
		this.passwordEncoder = passwordEncoder;
	}

	@GetMapping("/profile")
	public ModelAndView profilePage(@AuthenticationPrincipal User principal,
			@RequestParam(value = "passwordChangeRequired", required = false) boolean passwordChangeRequired) {
		ModelAndView mav = new ModelAndView("profile");
		mav.addObject("user", this.userService.requireUser(principal.getUsername()));
		mav.addObject("profileForm", new ProfileForm());
		mav.addObject("passwordForm", new ProfilePasswordForm());
		mav.addObject("passwordChangeRequired", passwordChangeRequired);
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
			mav.addObject("passwordForm", new ProfilePasswordForm());
			return mav;
		}
		this.userService.updateProfile(user.getId(), user.getEmail(), user.getPhone(), user.getAvatar(),
				profileForm.getDisplayName().trim());
		redirectAttributes.addFlashAttribute("successMessage", "显示名称已更新");
		return new ModelAndView("redirect:/profile");
	}

	@PostMapping("/profile/password")
	public ModelAndView changePassword(@AuthenticationPrincipal User principal,
			@Valid @ModelAttribute("passwordForm") ProfilePasswordForm form, BindingResult bindingResult,
			RedirectAttributes redirectAttributes) {
		var user = this.userService.requireUser(principal.getUsername());

		if (!bindingResult.hasFieldErrors("currentPassword")
				&& !this.passwordEncoder.matches(form.getCurrentPassword(), user.getPasswordHash())) {
			bindingResult.rejectValue("currentPassword", "password.mismatch", "当前密码不正确");
		}
		if (!bindingResult.hasErrors() && !form.getNewPassword().equals(form.getConfirmPassword())) {
			bindingResult.rejectValue("confirmPassword", "password.mismatch", "两次输入的新密码不一致");
		}
		if (bindingResult.hasErrors()) {
			ModelAndView mav = new ModelAndView("profile");
			mav.addObject("user", user);
			mav.addObject("profileForm", new ProfileForm());
			return mav;
		}

		this.userService.changePassword(user.getId(), form.getNewPassword());
		redirectAttributes.addFlashAttribute("successMessage", "密码已修改");
		return new ModelAndView("redirect:/profile");
	}

}
