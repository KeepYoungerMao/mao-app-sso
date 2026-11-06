package com.mao.sso.oauth;

import java.time.Clock;
import java.time.Instant;
import java.util.Base64;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;

/**
 * 面向公共客户端（{@code client_authentication_method=none}）的 Refresh Token 生成器。
 *
 * <p>Spring Authorization Server 官方的 {@code OAuth2RefreshTokenGenerator} 出于安全考量，
 * 对公共客户端的授权码流程一律不签发 refresh token（直接返回 null）。但 MCP 授权规范
 * （基于 RFC 8414 发现的 OAuth 流程）要求授权服务器支持公共客户端的 refresh token：
 * access token 默认仅 5 分钟有效，没有 refresh token，客户端每次过期都要重走浏览器
 * 交互授权，体验不可接受。</p>
 *
 * <p>本类复刻官方生成逻辑（随机密钥 + {@code TokenSettings.refreshTokenTimeToLive}），
 * 仅去掉「公共客户端排除」分支。公共客户端一律启用 PKCE（由 DCR 策略强制），
 * refresh token 窃取风险可控。</p>
 */
public final class PublicClientRefreshTokenGenerator implements OAuth2TokenGenerator<OAuth2RefreshToken> {

	private final StringKeyGenerator refreshTokenGenerator = new Base64StringKeyGenerator(
			Base64.getUrlEncoder().withoutPadding(), 96);

	private Clock clock = Clock.systemUTC();

	@Override
	public OAuth2RefreshToken generate(OAuth2TokenContext context) {
		if (context.getTokenType() == null || (!OAuth2TokenType.REFRESH_TOKEN.equals(context.getTokenType()))) {
			return null;
		}
		Instant issuedAt = this.clock.instant();
		Instant expiresAt = issuedAt
			.plus(context.getRegisteredClient().getTokenSettings().getRefreshTokenTimeToLive());
		return new OAuth2RefreshToken(this.refreshTokenGenerator.generateKey(), issuedAt, expiresAt);
	}

}
