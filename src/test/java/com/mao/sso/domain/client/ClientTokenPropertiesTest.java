package com.mao.sso.domain.client;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import com.mao.sso.api.config.ClientTokenProperties;
import com.mao.sso.api.client.ClientService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import com.mao.sso.support.IntegrationTestSupport;

/**
 * 客户端令牌有效期来自配置的验证。
 *
 * <p>{@code sso.token.*} 曾经写在 {@code SsoProperties} 里，拆分后由
 * {@link ClientTokenProperties} 承载。本类用一组<b>明显不同于默认值</b>的配置启动上下文，
 * 再创建客户端读回 {@link TokenSettings}，以此锁死「配置 → 注册表」这条链：</p>
 *
 * <ul>
 *   <li>配置被忽略（写死 15 分钟等）→ 断言失败；</li>
 *   <li>配置只绑到 Bean、没写进新建客户端 → 断言失败；</li>
 *   <li>属性名拼错导致绑定失败 → 上下文里的值仍是字段默认值，断言失败。</li>
 * </ul>
 *
 * <p>之所以单独一个测试类而不塞进 {@link ClientServiceTest}：属性覆盖是类级的，
 * 前者需要自己的应用上下文，混在一起会让其余用例默默跑在改过的配置下。</p>
 */
@SpringBootTest(properties = {
		"sso.token.access-token-ttl=PT45M",
		"sso.token.refresh-token-ttl=P7D",
		"sso.token.authorization-code-ttl=PT2M",
		"sso.token.reuse-refresh-tokens=true" })
class ClientTokenPropertiesTest extends IntegrationTestSupport {

	@Autowired
	private ClientService clientService;

	@Autowired
	private RegisteredClientRepository repository;

	@Test
	@DisplayName("新建客户端的令牌有效期取自 sso.token 配置，而不是写死的默认值")
	void createAppliesConfiguredTokenSettings() {
		String clientId = "ttl-" + UUID.randomUUID().toString().substring(0, 8);

		this.clientService.createClient(clientId, "TTL 客户端", null, List.of("none"),
				List.of("authorization_code"), "https://" + clientId + ".example.com/callback",
				List.of("openid"), false, true);

		RegisteredClient saved = this.repository.findByClientId(clientId);
		assertThat(saved).isNotNull();
		TokenSettings settings = saved.getTokenSettings();
		assertThat(settings.getAccessTokenTimeToLive()).isEqualTo(Duration.ofMinutes(45));
		assertThat(settings.getRefreshTokenTimeToLive()).isEqualTo(Duration.ofDays(7));
		assertThat(settings.getAuthorizationCodeTimeToLive()).isEqualTo(Duration.ofMinutes(2));
		assertThat(settings.isReuseRefreshTokens()).isTrue();
	}

}
