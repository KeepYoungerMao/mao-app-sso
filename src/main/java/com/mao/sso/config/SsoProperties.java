package com.mao.sso.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * mao-app-sso 业务配置（前缀 sso），全部支持环境变量覆盖。
 *
 * <p>敏感项（jwk.password、admin.password、clients[].client-secret）不提供默认值，
 * 必须通过环境变量注入，代码与仓库中不存在任何真实凭据。</p>
 */
@ConfigurationProperties(prefix = "sso")
public class SsoProperties {

	/** Authorization Server 对外 Issuer，必须与浏览器实际访问地址一致。 */
	private String issuerUrl = "http://localhost:8080";

	private final Jwk jwk = new Jwk();

	private final Token token = new Token();

	private final Admin admin = new Admin();

	private final Dcr dcr = new Dcr();

	private final Metadata metadata = new Metadata();

	public String getIssuerUrl() {
		return this.issuerUrl;
	}

	public void setIssuerUrl(String issuerUrl) {
		this.issuerUrl = issuerUrl;
	}

	public Jwk getJwk() {
		return this.jwk;
	}

	public Token getToken() {
		return this.token;
	}

	public Admin getAdmin() {
		return this.admin;
	}

	public Dcr getDcr() {
		return this.dcr;
	}

	public Metadata getMetadata() {
		return this.metadata;
	}

	/** JWT 签名密钥配置。 */
	public static class Jwk {

		/**
		 * 持久化 JWK Set（JSON）位置，支持 classpath: 与 file: 前缀。
		 * 生产环境必须配置，保证重启后历史 Token 可验证、支持密钥轮换。
		 */
		private String location = "";

		/** JWK Set 加密口令（如使用加密 JWK Set），通过环境变量注入。 */
		private String password = "";

		/**
		 * 是否允许未配置 location 时生成临时密钥。
		 * 仅 dev profile 开启；生产（prod profile）必须为 false。
		 */
		private boolean allowEphemeral = false;

		public String getLocation() {
			return this.location;
		}

		public void setLocation(String location) {
			this.location = location;
		}

		public String getPassword() {
			return this.password;
		}

		public void setPassword(String password) {
			this.password = password;
		}

		public boolean isAllowEphemeral() {
			return this.allowEphemeral;
		}

		public void setAllowEphemeral(boolean allowEphemeral) {
			this.allowEphemeral = allowEphemeral;
		}

	}

	/** Token 生命周期配置。 */
	public static class Token {

		private Duration accessTokenTtl = Duration.ofMinutes(15);

		private Duration refreshTokenTtl = Duration.ofDays(30);

		private Duration authorizationCodeTtl = Duration.ofMinutes(5);

		/** false 表示刷新时轮换 refresh token（OAuth 2.1 推荐）。 */
		private boolean reuseRefreshTokens = false;

		public Duration getAccessTokenTtl() {
			return this.accessTokenTtl;
		}

		public void setAccessTokenTtl(Duration accessTokenTtl) {
			this.accessTokenTtl = accessTokenTtl;
		}

		public Duration getRefreshTokenTtl() {
			return this.refreshTokenTtl;
		}

		public void setRefreshTokenTtl(Duration refreshTokenTtl) {
			this.refreshTokenTtl = refreshTokenTtl;
		}

		public Duration getAuthorizationCodeTtl() {
			return this.authorizationCodeTtl;
		}

		public void setAuthorizationCodeTtl(Duration authorizationCodeTtl) {
			this.authorizationCodeTtl = authorizationCodeTtl;
		}

		public boolean isReuseRefreshTokens() {
			return this.reuseRefreshTokens;
		}

		public void setReuseRefreshTokens(boolean reuseRefreshTokens) {
			this.reuseRefreshTokens = reuseRefreshTokens;
		}

	}

	/** 初始管理员配置（初始化逻辑幂等）。 */
	public static class Admin {

		private String username = "admin";

		private String email = "admin@mao.local";

		private String displayName = "系统管理员";

		/** 必须通过环境变量 SSO_ADMIN_PASSWORD 提供；为空则跳过初始化。 */
		private String password = "";

		public String getUsername() {
			return this.username;
		}

		public void setUsername(String username) {
			this.username = username;
		}

		public String getEmail() {
			return this.email;
		}

		public void setEmail(String email) {
			this.email = email;
		}

		public String getDisplayName() {
			return this.displayName;
		}

		public void setDisplayName(String displayName) {
			this.displayName = displayName;
		}

		public String getPassword() {
			return this.password;
		}

		public void setPassword(String password) {
			this.password = password;
		}

	}

	/**
	 * 动态客户端注册（RFC 7591 OAuth DCR）开关。
	 *
	 * <p>所有客户端必须预先在管理后台录入才能注册/授权。DCR 端点的作用是：
	 * 客户端提交 redirect_uri，服务端查表返回对应的固定 client_id。
	 * 未预录入的 redirect_uri 会被拒绝（400 invalid_redirect_uri）。</p>
	 */
	public static class Dcr {

		/** 是否启用动态客户端注册端点（/oauth2/register）。 */
		private boolean enabled = false;

		/**
		 * 是否要求调用方已登录且具备 ADMIN 角色。
		 * MCP 客户端等无凭据程序无法登录，需要开放注册时保持 false。
		 */
		private boolean requireAuthentication = false;

		/** 单 IP 每分钟最大注册请求次数（仅频率保护，非白名单）；0 表示不限流。 */
		private int maxRegistrationsPerMinute = 30;

		public boolean isEnabled() {
			return this.enabled;
		}

		public void setEnabled(boolean enabled) {
			this.enabled = enabled;
		}

		public boolean isRequireAuthentication() {
			return this.requireAuthentication;
		}

		public void setRequireAuthentication(boolean requireAuthentication) {
			this.requireAuthentication = requireAuthentication;
		}

		public int getMaxRegistrationsPerMinute() {
			return this.maxRegistrationsPerMinute;
		}

		public void setMaxRegistrationsPerMinute(int maxRegistrationsPerMinute) {
			this.maxRegistrationsPerMinute = maxRegistrationsPerMinute;
		}

	}

	/**
	 * 授权服务器发现元数据（RFC 8414）对外宣告内容。
	 *
	 * <p>Spring Authorization Server 默认不会宣告 {@code scopes_supported}，也默认不在
	 * {@code token_endpoint_auth_methods_supported} 中包含 {@code none}（public client）。
	 * 而 MCP / 桌面 / 移动端客户端普遍是 public client，且依赖元数据决定请求哪些 scope，
	 * 缺失这两项会让严格的客户端在进入动态注册之前就放弃流程。</p>
	 */
	public static class Metadata {

		/**
		 * 宣告的 {@code scopes_supported}。留空表示不宣告该字段。
		 * 建议与 {@code sso.dcr.allowed-scopes} 保持一致，避免「元数据允许、注册被拒」。
		 */
		private List<String> scopesSupported = new ArrayList<>(List.of("openid", "profile", "email"));

		/**
		 * 是否在 {@code token_endpoint_auth_methods_supported} 中宣告 {@code none}。
		 * public client（无密钥，依赖 PKCE）必须开启。
		 */
		private boolean allowPublicClients = true;

		/**
		 * 是否为发现端点与注册端点开放 CORS。
		 * RFC 7591 §4 与 MCP 规范建议授权服务器支持 CORS，浏览器内客户端需要。
		 * 仅放通 {@code /.well-known/**}、{@code /oauth2/jwks}、{@code /oauth2/register}、
		 * {@code /userinfo}，且不允许携带凭据。
		 */
		private boolean corsEnabled = true;

		/** CORS 允许的来源列表；{@code *} 表示任意来源。 */
		private List<String> corsAllowedOrigins = new ArrayList<>(List.of("*"));

		public List<String> getScopesSupported() {
			return this.scopesSupported;
		}

		public void setScopesSupported(List<String> scopesSupported) {
			this.scopesSupported = scopesSupported;
		}

		public boolean isAllowPublicClients() {
			return this.allowPublicClients;
		}

		public void setAllowPublicClients(boolean allowPublicClients) {
			this.allowPublicClients = allowPublicClients;
		}

		public boolean isCorsEnabled() {
			return this.corsEnabled;
		}

		public void setCorsEnabled(boolean corsEnabled) {
			this.corsEnabled = corsEnabled;
		}

		public List<String> getCorsAllowedOrigins() {
			return this.corsAllowedOrigins;
		}

		public void setCorsAllowedOrigins(List<String> corsAllowedOrigins) {
			this.corsAllowedOrigins = corsAllowedOrigins;
		}

	}

}
