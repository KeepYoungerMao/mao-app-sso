package com.mao.sso;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import com.mao.sso.support.IntegrationTestSupport;

/**
 * 应用上下文加载测试：验证所有 Bean（含授权服务器配置）可正常装配。
 */
@SpringBootTest
@AutoConfigureMockMvc
class AppTests extends IntegrationTestSupport {

	@Test
	@DisplayName("Spring 上下文加载成功")
	void contextLoads() {
	}

}
