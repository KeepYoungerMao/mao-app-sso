package com.mao.sso.domain.support;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;

/**
 * 审计上下文：解析当前操作人标识（写入 created_by / updated_by）。
 *
 * <p>来源：{@link SecurityContextHolder} —— 表单登录会话或管理 API 的 JWT 认证
 * （JWT 的 {@code sub} 即用户名，{@code auth.getName()} 直接返回）。</p>
 *
 * <p>无认证上下文（启动初始化、定时任务）时统一记为 {@value #SYSTEM_USER}。</p>
 */
public final class AuditContext {

	public static final String SYSTEM_USER = "system";

	private AuditContext() {
	}

	public static String currentUser() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication == null || !authentication.isAuthenticated()
				|| authentication instanceof AnonymousAuthenticationToken) {
			return SYSTEM_USER;
		}
		String name = authentication.getName();
		if (!StringUtils.hasText(name) || "anonymousUser".equals(name)) {
			return SYSTEM_USER;
		}
		// 审计列长度 50，超长截断防止 INSERT 失败
		return (name.length() > 50) ? name.substring(0, 50) : name;
	}

}
