package com.mao.sso.auth.config;

import java.util.ArrayList;
import java.util.List;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * 认证服务器的业务配置（前缀 sso）。
 *
 * <p>敏感项（jwk.password、admin.password）不提供默认值，
 * 必须通过外挂配置或环境变量注入，代码与仓库中不存在任何真实凭据。</p>
 *
 * <p><b>只使用 {@code @Getter} / {@code @Setter}，禁止使用 {@code @Data}：</b>
 * {@code @Data} 会生成 {@code toString()}，把 {@code jwk.password} 与 {@code admin.password}
 * 原样写进日志。</p>
 *
 * <p>注意：{@code sso.token.*}（新建客户端的默认 TokenSettings）与 {@code sso.admin-api.*}
 * 不在这里 —— 前者的消费者是领域层的 {@code ClientService}，后者属于管理 API。</p>
 */
@ConfigurationProperties(prefix = "sso")
@Getter
@Setter
public class SsoProperties {

	/** Authorization Server 对外 Issuer，必须与浏览器实际访问地址一致。 */
	private String issuerUrl = "http://localhost:8080";

	private final Jwk jwk = new Jwk();

	private final Admin admin = new Admin();

	private final Dcr dcr = new Dcr();

	private final Metadata metadata = new Metadata();

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

}
