package com.mao.sso.api.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Getter;
import lombok.Setter;

/**
 * 管理 API（资源服务器）的配置，前缀 {@code sso.admin-api}。
 *
 * <p>从认证服务器的 {@code SsoProperties} 里拆出来，是因为它的每一项都只服务
 * {@code /api/v1/admin/**}：开关、受众 client_id、所需角色、CORS 来源。</p>
 *
 * <p>管理接口以 OAuth2 Resource Server 形态暴露：调用方（管理控制台）先以授权码 + PKCE
 * 登录拿到 Access Token，再以 Bearer 方式调用。</p>
 *
 * <p><b>授权模型：按角色，不按 scope。</b>本服务只定义 {@code openid} / {@code profile}
 * 两个 scope，它们仅用于 OIDC claims 裁剪，不参与接口鉴权。管理接口要求 Access Token 的
 * {@code roles} claim 中包含 {@link #requiredRole}（默认 {@code ADMIN}），
 * 该 claim 由 {@code JwtClaimsCustomizer} 从用户角色写入。改角色后必须重新签发 Token。</p>
 *
 * <p><b>注意 {@link #clientId}</b>：领域层的 {@code ClientService} 通过
 * {@code @Value("${sso.admin-api.client-id}")} 读同一个 key（用于「不允许删除管理控制台自身」）。
 * 改这个属性名时要同步改那里，编译期不会报错。</p>
 */
@Getter
@Setter
@ConfigurationProperties("sso.admin-api")
public class AdminApiProperties {

	/** 是否启用管理 API 安全链；关闭后 {@code /api/v1/admin/**} 将落到普通 Web 链。 */
	private boolean enabled = true;

	/** 管理控制台自身的 client_id（V1 迁移已预置）：禁止被删除，避免失去运维入口。 */
	private String clientId = "mao-app-admin";

	/** 访问管理 API 所需角色（对应 roles 表的 code，大写比较）。 */
	private String requiredRole = "ADMIN";

	/** 允许跨域调用管理 API 的前端来源（管理控制台）。 */
	private List<String> corsAllowedOrigins = new ArrayList<>(List.of("*"));

}
