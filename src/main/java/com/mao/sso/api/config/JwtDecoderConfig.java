package com.mao.sso.api.config;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/**
 * 管理 API 链的 JWT 验签器。
 *
 * <p>验签与签名必须同源，因此这里注入的 {@code JWKSource} 就是认证服务器
 * {@code auth.config.JwkSourceConfig#jwkSource} 产出的那个 Bean。</p>
 *
 * <p><b>为什么能放在 api 包而依赖不破</b>：入参类型是 nimbus 的
 * {@link JWKSource}，不是项目内的类。Bean 由 Spring 容器按类型连接，
 * 所以资源服务器拿得到密钥，却不需要 import 认证服务器任何代码。</p>
 */
@Configuration(proxyBeanMethods = false)
public class JwtDecoderConfig {

	/**
	 * UserInfo 端点与 Bearer Token 校验共用的 JwtDecoder。
	 */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

}
