package com.mao.sso.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * mao-app-sso 业务配置（前缀 sso），全部支持环境变量覆盖。
 *
 * <p>敏感项（jwk.password、admin.password、clients[].client-secret）不提供默认值，
 * 必须通过环境变量注入，代码与仓库中不存在任何真实凭据。</p>
 *
 * <p><b>只使用 {@code @Getter} / {@code @Setter}，禁止使用 {@code @Data}：</b>
 * {@code @Data} 会生成 {@code toString()}，把 {@code jwk.password} 与 {@code admin.password}
 * 原样写进日志。</p>
 */
@ConfigurationProperties(prefix = "sso")
@Getter
@Setter
public class SsoProperties {

	/** Authorization Server 对外 Issuer，必须与浏览器实际访问地址一致。 */
	private String issuerUrl = "http://localhost:8080";

	private final Jwk jwk = new Jwk();

	private final Token token = new Token();

	private final Admin admin = new Admin();

	private final Dcr dcr = new Dcr();

	private final Metadata metadata = new Metadata();

	private final AdminApi adminApi = new AdminApi();

	/** JWT 签名密钥配置。 */
	@Getter
	@Setter
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

	}

	/** Token 生命周期配置。 */
	@Getter
	@Setter
	public static class Token {

		private Duration accessTokenTtl = Duration.ofMinutes(15);

		private Duration refreshTokenTtl = Duration.ofDays(30);

		private Duration authorizationCodeTtl = Duration.ofMinutes(5);

		/** false 表示刷新时轮换 refresh token（OAuth 2.1 推荐）。 */
		private boolean reuseRefreshTokens = false;

	}

	/** 初始管理员配置（初始化逻辑幂等）。 */
	@Getter
	@Setter
	public static class Admin {

		private String username = "admin";

		private String email = "admin@mao.local";

		private String displayName = "系统管理员";

		/** 必须通过环境变量 SSO_ADMIN_PASSWORD 提供；为空则跳过初始化。 */
		private String password = "";

	}

	/**
	 * 动态客户端注册（RFC 7591 OAuth DCR）开关。
	 *
	 * <p>所有客户端必须预先在管理后台录入才能注册/授权。DCR 端点的作用是：
	 * 客户端提交 redirect_uri，服务端查表返回对应的固定 client_id。
	 * 未预录入的 redirect_uri 会被拒绝（400 invalid_redirect_uri）。</p>
	 *
	 * <p>端点一旦启用即为匿名可调（{@code permitAll}）：它的消费方是 MCP、CLI、
	 * 桌面端这类无会话的程序客户端，任何基于登录态的鉴权都会把它们挡住。
	 * 需要限制来源时应在网络层（网关 / 内网 / IP 白名单）或 {@link #maxRegistrationsPerMinute}
	 * 上做，不要在这里加开关。</p>
	 */
	@Getter
	@Setter
	public static class Dcr {

		/** 是否启用动态客户端注册端点（/oauth2/register）。 */
		private boolean enabled = false;

		/** 单 IP 每分钟最大注册请求次数（仅频率保护，非白名单）；0 表示不限流。 */
		private int maxRegistrationsPerMinute = 30;

	}

	/**
	 * 授权服务器发现元数据（RFC 8414）对外宣告内容。
	 *
	 * <p>Spring Authorization Server 默认不会宣告 {@code scopes_supported}，也默认不在
	 * {@code token_endpoint_auth_methods_supported} 中包含 {@code none}（public client）。
	 * 而 MCP / 桌面 / 移动端客户端普遍是 public client，且依赖元数据决定请求哪些 scope，
	 * 缺失这两项会让严格的客户端在进入动态注册之前就放弃流程。</p>
	 */
	@Getter
	@Setter
	public static class Metadata {

		/**
		 * 宣告的 {@code scopes_supported}。留空表示不宣告该字段。
		 *
		 * <p>本服务只定义 {@code openid} 与 {@code profile} 两个 scope，且 scope 仅影响
		 * OIDC claims 的裁剪，<b>不参与接口鉴权</b>（鉴权一律按角色）。</p>
		 */
		private List<String> scopesSupported = new ArrayList<>(List.of("openid", "profile"));

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

	}

	/**
	 * 管理 API（{@code /api/v1/admin/**}）配置。
	 *
	 * <p>管理接口在本服务内以 OAuth2 Resource Server 形态暴露：调用方（管理控制台）
	 * 先以授权码 + PKCE 登录拿到 Access Token，再以 Bearer 方式调用。</p>
	 *
	 * <p><b>授权模型：按角色，不按 scope。</b>本服务只定义 {@code openid} / {@code profile}
	 * 两个 scope，它们仅用于 OIDC claims 裁剪，不参与接口鉴权。管理接口要求 Access Token 的
	 * {@code roles} claim 中包含 {@link #requiredRole}（默认 {@code ADMIN}），
	 * 该 claim 由 {@code JwtClaimsCustomizer} 从用户角色写入。</p>
	 */
	@Getter
	@Setter
	public static class AdminApi {

		/** 是否启用管理 API 安全链；关闭后 /api/v1/admin/** 将落到普通 Web 链。 */
		private boolean enabled = true;

		/** 管理控制台自身的 client_id（V1 迁移已预置）：禁止被删除，避免失去运维入口。 */
		private String clientId = "mao-app-admin";

		/** 访问管理 API 所需角色（对应 roles 表的 code，大写比较）。 */
		private String requiredRole = "ADMIN";

		/** 允许跨域调用管理 API 的前端来源（管理控制台）。 */
		private List<String> corsAllowedOrigins = new ArrayList<>(List.of("*"));

	}

}
