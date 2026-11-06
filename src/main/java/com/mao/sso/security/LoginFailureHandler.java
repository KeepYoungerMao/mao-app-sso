package com.mao.sso.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * 登录失败处理器。
 *
 * <p>防用户枚举：无论失败原因是“用户不存在”“密码错误”还是“账户被禁用/锁定”，
 * 对用户统一返回通用提示；详细原因仅在服务端日志中记录。</p>
 */
@Component
public class LoginFailureHandler extends SimpleUrlAuthenticationFailureHandler {

	private static final Logger log = LoggerFactory.getLogger(LoginFailureHandler.class);

	public LoginFailureHandler() {
		setDefaultFailureUrl("/login?error");
	}

	@Override
	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException exception) throws IOException, ServletException {
		String username = request.getParameter("username");
		log.info("登录失败: username={} reason={}", username, exception.getClass().getSimpleName());
		super.onAuthenticationFailure(request, response, exception);
	}

}
