package com.mao.sso.auth.portal;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;

import com.mao.sso.support.IntegrationTestSupport;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Session Cookie 安全属性端到端测试（真实 Tomcat 容器）。
 *
 * <p>MockMvc 不模拟 Servlet 容器下发 Session Cookie 的行为，
 * 因此使用 JDK 内置 HttpClient 访问真实端口验证 Cookie 属性
 * （HttpOnly / SameSite=Lax）与安全响应头。</p>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class SessionCookieSecurityTest extends IntegrationTestSupport {

	@LocalServerPort
	private int port;

	private HttpResponse<String> get(String path) throws Exception {
		HttpClient client = HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build();
		HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path)).GET().build();
		return client.send(request, HttpResponse.BodyHandlers.ofString());
	}

	@Test
	@DisplayName("Session Cookie 具备 HttpOnly 与 SameSite=Lax 属性")
	void sessionCookieHasSecurityAttributes() throws Exception {
		// 未认证访问受保护页面：容器创建会话并下发 Cookie
		HttpResponse<String> response = get("/profile");
		assertThat(response.statusCode()).isEqualTo(302);
		List<String> cookies = response.headers().allValues("Set-Cookie");
		assertThat(cookies).anyMatch((cookie) -> cookie.startsWith("SSO_SESSION="));
		assertThat(cookies).anyMatch((cookie) -> cookie.contains("HttpOnly"));
		assertThat(cookies).anyMatch((cookie) -> cookie.contains("SameSite=Lax"));
	}

	@Test
	@DisplayName("登录页在真实服务器返回安全响应头")
	void securityHeadersOnRealServer() throws Exception {
		HttpResponse<String> response = get("/login");
		assertThat(response.statusCode()).isEqualTo(200);
		assertThat(response.headers().firstValue("Content-Security-Policy").orElse(""))
			.contains("default-src 'self'");
		assertThat(response.headers().firstValue("X-Frame-Options").orElse("")).isEqualTo("DENY");
		assertThat(response.headers().firstValue("X-Content-Type-Options").orElse("")).isEqualTo("nosniff");
		assertThat(response.headers().firstValue("Referrer-Policy").orElse(""))
			.isEqualTo("strict-origin-when-cross-origin");
	}

}
