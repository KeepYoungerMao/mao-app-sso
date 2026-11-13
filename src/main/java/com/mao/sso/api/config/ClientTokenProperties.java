package com.mao.sso.api.config;

import java.time.Duration;

import com.mao.sso.api.client.ClientService;
import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

/**
 * 新建客户端时写入的默认 {@code TokenSettings} 快照。
 *
 * <p>Spring Authorization Server 没有「全局 Token TTL」这种设置：TTL 只存在于每个
 * {@code RegisteredClient.getTokenSettings()} 上。因此本配置的语义是
 * <b>新建客户端的默认值</b>，<b>修改它不影响已存在的客户端</b>。</p>
 *
 * <p>之所以独立成一个配置类、而不是留在 {@code SsoProperties} 里：它的唯一消费者是本包的
 * {@link ClientService}。放在认证服务器的配置类里会让领域层反过来依赖 auth 包。</p>
 */
@Getter
@Setter
@ConfigurationProperties("sso.token")
public class ClientTokenProperties {

	private Duration accessTokenTtl = Duration.ofMinutes(15);

	private Duration refreshTokenTtl = Duration.ofDays(30);

	private Duration authorizationCodeTtl = Duration.ofMinutes(5);

	/** false 表示刷新时轮换 refresh token（OAuth 2.1 推荐）。 */
	private boolean reuseRefreshTokens = false;

}
