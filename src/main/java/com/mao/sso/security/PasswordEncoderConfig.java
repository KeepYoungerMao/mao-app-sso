package com.mao.sso.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 密码编码器配置：Argon2id（当前 Spring Security crypto 内置实现，无需额外依赖）。
 *
 * <p>参数参照 OWASP 密码存储备忘单：m=19MiB (19456 KiB)、t=2、p=1、salt=16B、hash=32B。</p>
 *
 * <p>该 Bean 同时被两处使用：</p>
 * <ul>
 *   <li>用户密码哈希（DaoAuthenticationProvider 自动装配）</li>
 *   <li>OAuth 客户端密钥校验 —— Spring Authorization Server 的
 *       ClientSecretAuthenticationProvider 会从容器中获取 PasswordEncoder Bean，
 *       因此客户端密钥同样以 Argon2id 哈希持久化，不明文存储。</li>
 * </ul>
 */
@Configuration
public class PasswordEncoderConfig {

	@Bean
	public PasswordEncoder passwordEncoder() {
		return new Argon2PasswordEncoder(16, 32, 1, 19456, 2);
	}

}
