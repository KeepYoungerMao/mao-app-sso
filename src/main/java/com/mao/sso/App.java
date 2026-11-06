package com.mao.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

/**
 * mao-app-sso：基于 Spring Authorization Server 的 OAuth 2.1 / OpenID Connect 1.0 统一认证中心。
 */
@SpringBootApplication
@ConfigurationPropertiesScan
public class App {

	public static void main(String[] args) {
		SpringApplication.run(App.class, args);
	}

}
