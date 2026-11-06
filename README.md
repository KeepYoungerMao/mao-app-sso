# mao-app-sso — OAuth 2.1 / OpenID Connect 1.0 统一认证中心

基于 **Spring Boot 4.1.2 + Spring Security 7.1.1 + Spring Authorization Server 7.1.1** 的统一用户认证中心，
为其他业务系统提供标准的 OAuth 2.1 / OIDC 1.0 认证服务（授权码 + PKCE + Refresh Token + JWT）。

## 功能特性

| 能力 | 说明 |
| --- | --- |
| OAuth 2.1 授权码模式 | `/oauth2/authorize` + `/oauth2/token` |
| PKCE（强制 S256） | 框架仅接受 `S256`；客户端可通过 `requireProofKey` 强制 PKCE |
| Refresh Token | 默认轮换（`reuseRefreshTokens=false`），旧令牌自动失效 |
| OpenID Connect 1.0 | `/.well-known/openid-configuration`、ID Token、`/userinfo` |
| JWT Access Token | RS256 签名，`/oauth2/jwks` 公钥端点，最小化 Claims |
| OAuth Discovery | `/.well-known/oauth-authorization-server`（RFC 8414） |
| 用户体系 | 用户名/邮箱登录、Argon2id 密码哈希、启用/锁定/过期四态、RBAC 角色 |
| 客户端持久化 | 官方 JDBC 实现，密钥哈希存储，支持 public / confidential 客户端 |
| 数据库持久化 | Flyway 迁移，授权数据全部入库，重启不丢状态 |
| 安全加固 | 双 SecurityFilterChain、CSRF、CORS 默认拒绝（仅发现端点可按需放通）、安全响应头、防用户枚举、防开放重定向 |
| 客户端管理界面 | `/admin/clients` Web 管理页（创建、列表、删除、密钥管理） |
| 动态客户端注册（DCR） | RFC 7591 `/oauth2/register`，按 redirect_uri 查表返回预录入的固定 client_id，未预录入则拒绝 |

**明确不支持**：Implicit Grant、Resource Owner Password Grant、任意 `redirect_uri`（全部需预录入）、明文密码/密钥存储；
所有客户端必须在管理后台预先录入。DCR 端点仅返回已预录入客户端的固定 client_id，不插入新记录。

## 技术栈与版本兼容性

本项目基于当前（2026-10）可解析的正式版本构建，**未使用任何已废弃 API**：

| 组件 | 版本 | 说明 |
| --- | --- | --- |
| JDK | 25 | `maven.compiler.release=25` |
| Spring Boot | 4.1.1 | 父 POM 管理全部依赖版本 |
| Spring Security | 7.1.1 | 由 Boot BOM 管理 |
| Spring Authorization Server | 7.1.1 | 由 Boot BOM 管理（`OAuth2AuthorizationServerConfigurer` 已并入 spring-security-config） |
| Spring Data JPA / Hibernate | ORM 7.4.5 | 实体审计（`created_at` / `updated_at`） |
| Flyway | 12.4.0 | 自动配置位于独立模块 `spring-boot-flyway`（Boot 4 变化） |
| Thymeleaf | 3.1.5.RELEASE | + `thymeleaf-extras-springsecurity6` 3.1.5（Boot BOM 管理） |
| MySQL Connector/J | 9.x | Boot BOM 管理 |
| Testcontainers | 2.0.5 | 注意 2.x 起 artifact 更名为 `testcontainers-mysql` / `testcontainers-junit-jupiter` |
| BouncyCastle | 1.86 | Spring Security 7 的 `Argon2PasswordEncoder` 基于 BC 实现，**必须显式引入** |

### 相对旧教程的关键差异（重要）

1. **`OAuth2AuthorizationServerConfigurer` 已从 Spring Authorization Server 移入 spring-security-config**
   （包名 `org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization`），
   使用方式为 `http.oauth2AuthorizationServer(...)`。
2. **Flyway 自动配置移至 `spring-boot-flyway` 模块**，仅引入 `flyway-core` 不会生效。
3. **`@AutoConfigureMockMvc` 位于 `org.springframework.boot.webmvc.test.autoconfigure`**。
4. **Argon2PasswordEncoder 需要 BouncyCastle**（`bcprov-jdk18on`），否则运行期 `NoClassDefFoundError`。
5. **授权记录中的 Principal 必须使用 Spring Security 内置 `User`**：`JdbcOAuth2AuthorizationService`
   用 Jackson 3 序列化授权属性，`CoreJacksonModule` 的多态类型白名单只允许框架内置类型
   （自定义 `UserDetails` 会在换取 Token 时反序列化失败）。业务属性按用户名查询数据库补充。
6. **公共客户端 refresh token 由自定义生成器签发**：SAS 官方 `OAuth2RefreshTokenGenerator`
   对公共客户端（认证方式 none）的授权码流程一律不返回 refresh token，且其
   `PublicClientAuthenticationConverter/Provider` 也不处理公共客户端的 refresh 请求
   （无 `code_verifier`）。本项目通过 `oauth/PublicClientRefreshTokenGenerator` +
   `PublicClientRefreshAuthenticationConverter` + `PublicClientRefreshAuthenticationProvider`
   三件套补齐，MCP 客户端因此可以静默续期（见 `AuthorizationServerConfig` 的
   `authorizationServerTokenGenerator` 与 `SecurityConfig` 的 `clientAuthentication` 配置）。
7. **JWT Claims 中的集合必须使用白名单内的类型**（如 `ArrayList`）：授权 Token 的 claims 会持久化到
   `oauth2_authorization.access_token_metadata`，`List.of()` 的 `ImmutableCollections$ListN` 无法反序列化。
8. Spring Boot 4 起 `spring-boot-starter-web` 更名为 `spring-boot-starter-webmvc`。

## 快速开始

### 1. 环境要求

- JDK 25+
- Maven 3.9+
- MySQL 8.0+（本地可用 Docker 快速启动）

```bash
# 本地 MySQL（Docker）
docker run -d --name mao-sso-mysql -p 3306:3306 \
  -e MYSQL_ROOT_PASSWORD=root \
  -e MYSQL_DATABASE=mao_sso \
  mysql:8.0 --character-set-server=utf8mb4 --collation-server=utf8mb4_unicode_ci
```

### 2. 配置环境变量

所有敏感信息均通过环境变量注入，代码与仓库中**不存在任何真实凭据**：

```bash
# 必填：数据库与初始管理员密码（无默认值）
export SSO_DATASOURCE_URL="jdbc:mysql://localhost:3306/mao_sso?useSSL=false&allowPublicKeyRetrieval=true&preserveInstants=true&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true"
export SSO_DATASOURCE_USERNAME=root
export SSO_DATASOURCE_PASSWORD=root
export SSO_ADMIN_PASSWORD='Admin@2026!'        # 初始管理员密码（不配置则不创建管理员）

# 可选：保密客户端密钥（不配置则启动时生成随机密钥并打印 WARN 日志）
export SSO_CLIENT_SECRET='web-client-secret'

# 可选：对外 Issuer（必须与浏览器实际访问地址一致）
export SSO_ISSUER_URL=http://localhost:8080
```

### 3. 启动

```bash
mvn spring-boot:run
```

启动后访问 <http://localhost:8080/>，使用 `admin` + 你设置的 `SSO_ADMIN_PASSWORD` 登录。

> 默认激活 `dev` profile（允许临时签名密钥，重启后历史 Token 失效，仅限开发）。
> 生产环境必须激活 `prod` profile 并配置持久化 JWK，见下文。

### 4. 一分钟验证

```bash
# OIDC Discovery
curl -s http://localhost:8080/.well-known/openid-configuration | head

# JWKS
curl -s http://localhost:8080/oauth2/jwks
```

## 项目结构

```
src/main/java/com/mao/sso/
├── App.java                          # 启动类（@ConfigurationPropertiesScan）
├── common/BaseEntity.java            # 审计基类（created_at / updated_at）
├── config/
│   ├── SsoProperties.java            # sso.* 配置（issuer/jwk/token/admin/clients）
│   └── JpaConfig.java                # JPA Auditing
├── security/
│   ├── SecurityConfig.java           # 双 SecurityFilterChain + 安全头/CORS/CSRF
│   ├── AuthorizationServerConfig.java# JWKSource / JwtDecoder / 官方 JDBC 服务 / AuthorizationServerSettings
│   ├── PasswordEncoderConfig.java    # Argon2id（OWASP 参数）
│   ├── UserDetailsServiceImpl.java   # 数据库 UserDetailsService（用户名或邮箱）
│   ├── JwtClaimsCustomizer.java      # Access Token roles / ID Token name/email claims
│   ├── LoginSuccessHandler.java      # 登录成功跳转（防开放重定向）
│   └── LoginFailureHandler.java      # 登录失败通用提示（防用户枚举）
├── user/
│   ├── User.java / Role.java         # 实体（Bean Validation）
│   ├── UserRepository / RoleRepository
│   ├── UserService.java              # 业务逻辑
│   └── UserInitializer.java          # 角色 + 初始管理员（幂等，无默认密码）
├── oauth/
│   ├── ClientService.java            # 客户端CRUD服务
│   ├── PreRegisteredClientProvider.java  # DCR查表Provider
│   ├── DcrRateLimiter.java           # DCR限流器
│   ├── DcrRejectedException.java     # DCR拒绝异常
│   ├── DcrResponseToken.java         # DCR响应Token
│   ├── PublicClientRefreshTokenGenerator.java
│   ├── PublicClientRefreshAuthenticationConverter.java
│   ├── PublicClientRefreshAuthenticationProvider.java
│   └── AuthorizationConsentController.java  # 授权确认页
├── web/                              # 登录/首页/资料/管理/登出/错误页 Controller
└── tools/JwkGenerator.java           # 生产 JWK Set 生成工具

src/main/resources/
├── application.yml / application-dev.yml / application-prod.yml
├── db/migration/V1..V4.sql           # 用户表 + SAS 官方三张表
├── templates/                        # Thymeleaf 页面（login/consent/home/profile/admin/error）
└── static/{css,js}/
```

## 数据库设计

Flyway 版本化迁移（`src/main/resources/db/migration`），用户表自建、OAuth 表**完全复用官方 schema**：

| 表 | 来源 | 说明 |
| --- | --- | --- |
| `users` | 自建 | 用户主表，密码哈希、四态账户字段、时间戳 |
| `roles` | 自建 | 角色（`ROLE_USER` / `ROLE_ADMIN`，迁移脚本预置） |
| `user_roles` | 自建 | 用户-角色多对多（外键级联删除） |
| `oauth2_registered_client` | [官方 schema](https://docs.spring.io/spring-authorization-server/reference/core/configuration/jpa.html) | OAuth 客户端（+ client_id 唯一索引） |
| `oauth2_authorization` | 官方 schema | 授权记录（授权码/Token/元数据，+ 2 个查询索引） |
| `oauth2_authorization_consent` | 官方 schema | 授权同意记录 |

设计要点：

- 主键 `BIGINT AUTO_INCREMENT`（业务表）/ `varchar(100)`（OAuth 表，与官方一致）；
- 唯一约束：`users.username`、`users.email`、`roles.code`、`oauth2_registered_client.client_id`；
- 外键：`user_roles` 双向外键 + `ON DELETE CASCADE`；
- 时间字段统一 `TIMESTAMP(6)`，UTC 存取（Hibernate `jdbc.time_zone=UTC` + MySQL 连接串
  `preserveInstants=true&connectionTimeZone=UTC`）；
- 迁移脚本兼容 MySQL 与 H2（MySQL 兼容模式），可在任意环境执行；
- **不保存明文密码与明文客户端密钥**。

## OAuth 客户端管理

所有 OAuth 客户端必须在管理后台预先录入。登录后（具有 ADMIN 角色）访问 `/admin/clients` 页面进行管理：

- **新建客户端**：填写 client_id、client_name、认证方式、授权类型、redirect_uri、scope 等信息
- **查看列表**：展示所有已注册客户端的核心信息
- **重新生成密钥**：仅 confidential 客户端支持
- **删除客户端**：直接从数据库删除

预录入的客户端自动支持 DCR 动态注册：客户端提交 redirect_uri 后，服务端查表返回对应的固定 client_id，无需额外配置。

### 动态客户端注册（DCR，RFC 7591）

DCR 端点 `/oauth2/register` 可用于让 WorkBuddy MCP 等客户端自助获取 client_id。
**不再随机生成新客户端，而是按 redirect_uri 查表返回已预录入的客户端。**

```bash
# DCR 请求示例（客户端提交 redirect_uri，不提供 client_id）
curl -i http://127.0.0.1:8080/oauth2/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"我的MCP客户端",
       "redirect_uris":["workbuddy://workbuddy/mcp/my-connector/oauth/callback"],
       "grant_types":["authorization_code","refresh_token"],
       "token_endpoint_auth_method":"none"}'
# 如果 redirect_uri 已预录入 → 201 {client_id: "my-connector", ...}
# 如果 redirect_uri 未预录入 → 400 invalid_redirect_uri
```

端点地址会通过 `/.well-known/oauth-authorization-server` 的 `registration_endpoint` 对外宣告。

配置项（`sso.dcr`）：

| 配置 / 环境变量 | 默认值（dev / prod） | 说明 |
| --- | --- | --- |
| `enabled` / `SSO_DCR_ENABLED` | `true` / `false` | 是否启用注册端点 |
| `require-authentication` / `SSO_DCR_REQUIRE_AUTHENTICATION` | `false` / `true` | true 时仅 ADMIN 可调 DCR |
| `max-registrations-per-minute` / `SSO_DCR_RATE_LIMIT` | `30` | 单 IP 每分钟请求上限，0 不限 |

> 说明：OIDC 版注册端点 `/connect/register` 未启用——Spring Authorization Server 的该实现强制校验 initial access token，无法匿名开放，暴露它只会得到一个必然失败的端点。

### 发现元数据（`sso.metadata`，RFC 8414）

Spring Authorization Server 默认**不宣告** `scopes_supported`，也不在 `token_endpoint_auth_methods_supported`
中包含 `none`（public client）。而 MCP / 桌面 / 移动端客户端几乎都是 public client，且要靠元数据决定请求哪些
scope——这两项缺失会让严格的客户端在进入动态注册之前就放弃。本项目的 `sso.metadata` 段用于补齐：

| 配置 / 环境变量 | 默认值 | 说明 |
| --- | --- | --- |
| `scopes-supported` / `SSO_METADATA_SCOPES` | `openid,profile,email,userId,userInfo,aksk,mcp:read` | 宣告 `scopes_supported`，建议与 `sso.dcr.allowed-scopes` 保持一致 |
| `allow-public-clients` / `SSO_METADATA_ALLOW_PUBLIC_CLIENTS` | `true` | 在 `token_endpoint_auth_methods_supported` 中追加 `none` |
| `cors-enabled` / `SSO_METADATA_CORS_ENABLED` | `true` | 是否为发现/JWKS/注册端点开放跨域 |
| `cors-allowed-origins` / `SSO_METADATA_CORS_ORIGINS` | `*` | 允许的来源；不携带凭据 |

CORS 只放通 `/.well-known/oauth-authorization-server`、`/.well-known/openid-configuration`、
`/oauth2/jwks`、`/oauth2/register`、`/userinfo`，其余端点仍沿用「默认拒绝」。

> 实现注记：授权服务器端点是 Filter 而非 Controller，OPTIONS 预检既不会被授权服务器链的 securityMatcher 命中，
> 也无法交给 Spring MVC 的处理器映射处理（都会得到 403 `Invalid CORS request`）。
> 因此预检由 `SecurityConfig.DiscoveryPreFlightFilter` 在安全过滤链之前单独应答。

### MCP 资源服务器接入示例

以「MCP 服务部署在 `http://223.113.240.17:30549`，SSO 在本机 `http://127.0.0.1:8080`」为例，完整链路：

```
MCP 客户端 ──GET /mcp──────────────────────► MCP 服务器
           ◄──401 + WWW-Authenticate────────
MCP 客户端 ──GET /.well-known/oauth-protected-resource─► MCP 服务器
           ◄──{resource, authorization_servers:[http://127.0.0.1:8080], scopes_supported}──
MCP 客户端 ──GET /.well-known/oauth-authorization-server─► SSO  ← 必须匿名可读
           ◄──{issuer, registration_endpoint, scopes_supported, ...}──
MCP 客户端 ──POST /oauth2/register──────────► SSO（DCR，public client + PKCE）
           ◄──201 {client_id}────────────────
浏览器     ──GET /oauth2/authorize?...&resource=...──► SSO → /login → /oauth2/consent
           ◄──302 redirect_uri?code=...&state=...───
MCP 客户端 ──POST /oauth2/token（code + code_verifier）─► SSO
           ◄──200 {access_token, refresh_token}──────
MCP 客户端 ──GET /mcp + Authorization: Bearer ...──► MCP 服务器（校验由资源服务器负责）
```

接入时必须对齐的三处：

1. **issuer 必须逐字符等于资源服务器宣告的 `authorization_servers`**。
   若 MCP 宣告 `http://127.0.0.1:8080`，`sso.issuer-url` 就不能是 `http://localhost:8080`
   （RFC 8414 要求 `metadata.issuer` 与发现所用标识完全一致，否则严格客户端直接放弃）。
2. **元数据要宣告 `none` 与 `scopes_supported`**（见上一小节）。
3. **redirect_uri 必须命中 `sso.dcr.allowed-redirect-uri-patterns`**。
   自定义协议（如 `workbuddy://workbuddy/mcp/.../oauth/callback`）由第三条正则
   `^(?!http)[a-zA-Z][a-zA-Z0-9+.\-]*://.+` 覆盖。

> 已知边界：Spring Authorization Server 7.1 未实现 RFC 8707（Resource Indicators），
> 授权请求中的 `resource` 参数会被忽略（不会报错），Access Token 的 `aud` 是 **client_id**
> 而不是资源服务器地址。若后续资源服务器要按 `aud` 校验，需要自行通过
> `OAuth2TokenCustomizer<JwtEncodingContext>` 把资源标识写入 `aud`。

### 自定义协议重定向中间页（MCP 桌面客户端必读）

Chromium 内核浏览器（Edge / Chrome）对**表单 POST 提交后服务器 302 跳转到自定义协议**
（`workbuddy://`、`myapp://` 等）会**静默丢弃**——不弹窗、不跳转、不报错，表现为
「点击同意授权后页面毫无反应」（授权码其实已签发）。因此本项目对授权端点做了处理：
当授权响应要跳转到非 http(s) 协议时，不直接 302，而是渲染一个**中间页**
（`security/CustomSchemeRedirectFilter`），页面上给出指向该地址的普通链接，
用户点击后浏览器才会唤起系统的「打开应用」弹窗，流程继续。

- 仅拦截 **POST** 产生的重定向（授权确认页提交/拒绝授权）；GET 直达授权端点
  的重定向保持原样（该路径验证可用）。
- 中间页不含内联脚本/样式，符合本站 CSP；页面同时展示可复制的完整回跳地址。
- 测试见 `CustomSchemeRedirectTest`；`tools/e2e-mcp-flow.py` 已适配（自动从中间页提取链接）。

本地联调可直接跑 `tools/e2e-mcp-flow.py`（需先启动应用）：它会完整模拟
「DCR → 授权码 + PKCE → 登录 → 授权确认 → 中间页 → 换 Token → refresh 续期」
并打印 Access Token 的 Claims。

## 浏览器操作说明（完整授权码流程）

1. 浏览器打开授权 URL（如下），未登录 → 跳转 `/login`；
2. 输入用户名/邮箱 + 密码登录 → 自动跳回授权端点；
3. 首次授权该客户端 → 展示**授权确认页**（可勾选/取消 scope，或拒绝）；
   （注意：仅请求 `openid` 单个 scope 时 SAS 会跳过授权确认页，直接发码）
4. 同意后 → 302 到 `redirect_uri?code=...&state=...`；若 `redirect_uri` 是自定义协议
   （如 `workbuddy://`），则先渲染**中间页**，需点击页内链接才会唤起客户端应用
   （Chromium 会静默丢弃 POST 后的自定义协议重定向，详见上文「自定义协议重定向中间页」）；
5. 客户端用授权码 + `code_verifier` 到 `/oauth2/token` 换取 Token；
6. 之后同一用户再次授权同一客户端（已同意范围）→ 直接下发授权码，不再弹确认页；
7. 浏览器退出：右上角「退出登录」→ `/logout` → 登出结果页（会话失效）。

授权 URL 示例（`code_challenge` = `base64url(sha256(code_verifier))`）：

```
http://localhost:8080/oauth2/authorize?response_type=code&client_id=mao-web-client
  &scope=openid%20profile%20email
  &redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Flogin%2Foauth2%2Fcode%2Fmao-web-client
  &state=xyz&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256
```

## curl 示例

以下示例演示无浏览器参与的服务端流程（用 cookie jar 维护会话）：

```bash
BASE=http://localhost:8080
CLIENT_ID=mao-web-client
CLIENT_SECRET=web-client-secret          # 与启动时配置一致
REDIRECT_URI=http://localhost/callback
CODE_VERIFIER=$(openssl rand -base64 48 | tr '+/' '-_' | tr -d '=\n')
CODE_CHALLENGE=$(printf %s "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '=\n')
STATE=$(uuidgen)

# 1) 授权请求（未登录 → 302 到 /login）
curl -i -c jar.txt "$BASE/oauth2/authorize?response_type=code&client_id=$CLIENT_ID\
&scope=openid%20profile%20email&redirect_uri=$REDIRECT_URI&state=$STATE\
&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

# 2) 登录（从登录页 HTML 中提取 _csrf 值，或先 GET /login 获取）
CSRF=$(curl -s -c jar.txt "$BASE/login" | grep -oP 'name="_csrf" value="\K[^"]+')
curl -i -b jar.txt -c jar.txt -X POST "$BASE/login" \
  -d "username=admin&password=$SSO_ADMIN_PASSWORD&_csrf=$CSRF"

# 3) 再次授权（需要授权确认 → 302 到 /oauth2/consent）
curl -i -b jar.txt -c jar.txt "$BASE/oauth2/authorize?response_type=code&client_id=$CLIENT_ID\
&scope=openid%20profile%20email&redirect_uri=$REDIRECT_URI&state=$STATE\
&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256"

# 4) 提交授权确认（从 /oauth2/consent 页面获取 consent state）
CONSENT_STATE=<上一步 302 Location 中的 state 参数>
CSRF2=$(curl -s -b jar.txt -c jar.txt "$BASE/oauth2/consent?client_id=$CLIENT_ID&scope=openid%20profile%20email&state=$CONSENT_STATE" | grep -oP 'name="_csrf" value="\K[^"]+')
LOCATION=$(curl -s -o /dev/null -w '%{redirect_url}' -b jar.txt -c jar.txt -X POST "$BASE/oauth2/authorize" \
  -d "client_id=$CLIENT_ID&state=$CONSENT_STATE&scope=openid&scope=profile&scope=email&_csrf=$CSRF2")
CODE=$(printf %s "$LOCATION" | grep -oP 'code=\K[^&]+')

# 5) 换取 Token
TOKEN_JSON=$(curl -s -X POST "$BASE/oauth2/token" \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=authorization_code&code=$CODE&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER")
echo "$TOKEN_JSON"
ACCESS_TOKEN=$(printf %s "$TOKEN_JSON" | grep -oP '"access_token":"\K[^"]+')
REFRESH_TOKEN=$(printf %s "$TOKEN_JSON" | grep -oP '"refresh_token":"\K[^"]+')

# 6) UserInfo
curl -s "$BASE/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN"

# 7) Refresh Token 轮换
curl -s -X POST "$BASE/oauth2/token" -u "$CLIENT_ID:$CLIENT_SECRET" \
  -d "grant_type=refresh_token&refresh_token=$REFRESH_TOKEN"

# 8) Discovery / JWKS
curl -s "$BASE/.well-known/openid-configuration"
curl -s "$BASE/oauth2/jwks"
```

> 提示：`/oauth2/authorize` 的 POST（授权确认）由 `state` 参数提供 CSRF 防护（RFC 6749 要求），
> 安全链对该端点豁免 CSRF；其余表单（登录、资料修改、管理操作）均需 CSRF Token。

## 测试

```bash
mvn clean verify
```

**测试数据库策略**：优先使用 Testcontainers MySQL（与生产完全一致）；当前环境无 Docker 时
自动回退到 H2（MySQL 兼容模式）并在日志打印 WARN，同一套集成测试可在任意环境执行。

测试覆盖（67 个用例，正常 + 失败流程）：

| 测试类 | 覆盖 |
| --- | --- |
| `PasswordEncoderTest` | Argon2id 编码/校验/加盐/算法标识 |
| `DatabaseMigrationTest` | 迁移应用、幂等、表齐全、角色种子、client_id 唯一约束 |
| `UserServiceTest` | 创建、唯一约束、密码/状态更新、未知角色 |
| `UserInitializationTest` | 初始化幂等、角色存在、无默认密码 |
| `OAuthClientInitializerTest` | ~~已移除~~ 客户端统一走管理页面预录入 |
| `LoginFlowTest` | 登录成功/失败/未知用户/禁用/锁定/邮箱登录、CSRF、未认证、权限不足、登出、安全头、CORS、防开放重定向 |
| `OAuthAuthorizationCodeFlowTest` | 完整授权码流程（登录+确认+PKCE+Token+UserInfo+Refresh 轮换+旧 Refresh 失效）、无重复授权、公共客户端（含 refresh 静默续期）、授权码一次性、错误 verifier |
| `OAuthNegativeFlowTest` | PKCE 缺失、`plain` 方法、非法 redirect_uri（不重定向）、非法 scope、未知 client、Implicit、Password Grant、错误客户端密钥、UserInfo 未认证/伪造 Token |
| `OidcDiscoveryTest` | OIDC Discovery、RFC 8414 元数据、仅安全授权类型、JWKS、JWKS 无私钥 |
| `ExternalJwkSourceTest` | 外部 JWK Set 文件加载（生产密钥路径） |
| `SessionCookieSecurityTest` | 真实服务器 Cookie 属性（HttpOnly/SameSite）、安全响应头 |
| `CustomSchemeRedirectTest` | 自定义协议重定向中间页（POST→200 中间页+链接可换 token、http 保持 302、GET 直达保持 302、拒绝授权错误态） |

## 生产部署注意事项

### 1. 签名密钥（必须）

```bash
# 生成持久化 JWK Set（含 RSA 私钥）
mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
java -cp "target/classes;$(cat target/cp.txt)" com.mao.sso.tools.JwkGenerator /secure/path/jwk.json

export SSO_JWK_LOCATION=/secure/path/jwk.json     # 支持 file: / classpath:
```

- `prod` profile 下未配置 `SSO_JWK_LOCATION` **启动直接失败**（绝不静默使用临时密钥）；
- 临时密钥（仅 dev）重启后历史 Token 全部失效；
- **密钥轮换**：生成包含新旧两个密钥（不同 `kid`）的 JWK Set，JWKS 端点公开全部公钥，
  签名使用第一个密钥；轮换时交换顺序即可平滑过渡。

### 2. 激活生产 profile

```bash
SPRING_PROFILES_ACTIVE=prod mvn spring-boot:run    # 或 java -jar mao-app-sso-1.0.0.jar
```

`prod` profile 自动启用：HSTS、`Secure` Cookie、关闭调试日志、禁止临时密钥。

### 3. 其他必做项

- **Issuer**：`SSO_ISSUER_URL` 必须是浏览器可达的 HTTPS 地址（与反向代理对外地址一致）；
- **HTTPS**：生产必须 TLS 终止于代理（Nginx/ALB），应用层 `SSO_SESSION_COOKIE_SECURE=true` 已随 prod 生效；
- **数据库**：独立账号 + 最小权限，定期备份 `oauth2_authorization`（含未过期 Token）；
- **凭据**：`SSO_ADMIN_PASSWORD`、`SSO_CLIENT_SECRET` 通过密钥管理系统注入，禁止写入镜像与仓库；
- **`oauth2_authorization` 索引**：Token 查询为全表扫描条件之一，高并发场景可按需补充
  `authorization_code_value` / `access_token_value` 前缀索引；
- **日志脱敏**：应用日志不输出密码、Token、客户端密钥；生产不开启 `include-message` 等错误详情。

## 安全设计说明

- **双 SecurityFilterChain**：链 1（`@Order(1)`）仅匹配授权服务器端点（`/oauth2/**`、`/userinfo`、`/.well-known/**`），
  启用 OIDC 与自定义授权确认页；链 2（`@Order(2)`）负责登录/登出/页面，CSRF 默认启用。
- **PKCE**：框架仅接受 `S256`；客户端可配置 `requireProofKey` 强制。
- **密码**：Argon2id（m=19MiB, t=2, p=1, salt=16B, hash=32B）；**客户端密钥**同样哈希后持久化，
  校验复用同一 `PasswordEncoder` Bean。
- **Session**：`SSO_SESSION` Cookie（HttpOnly、SameSite=Lax、prod 下 Secure）、30 分钟超时、
  `changeSessionId` 防会话固定（保留授权请求状态）。
- **防用户枚举**：登录失败统一返回「用户名或密码错误」，不区分不存在/禁用/锁定（详情仅服务端日志）。
- **防开放重定向**：登录成功跳转仅允许站内相对地址；授权端点对无效 `redirect_uri` 不执行重定向。
- **CORS 默认拒绝**：任何跨域请求（含预检）返回 403；同源请求不受影响。
- **安全响应头**：CSP（`default-src 'self'`、无 unsafe-inline）、`X-Frame-Options: DENY`、
  `Referrer-Policy`、`nosniff`、prod 下 HSTS。
- **Token Claims 最小化**：Access Token 仅含 `sub`/`iat`/`exp`/`roles`；ID Token 含 `name`/`email`（按 scope）；
  不含密码与敏感个人信息。
- **Principal 序列化约束**：授权记录中的 Principal 使用 Spring Security 内置 `User`
  （Jackson 多态白名单要求），业务属性按需查库。

## 常见问题

**Q：启动报 `Schema validation: missing table`？**
确认 Flyway 已执行（`spring-boot-flyway` 依赖存在且 `spring.flyway.enabled=true`）；表结构只由迁移管理，
不要启用 `ddl-auto=update`。

**Q：换取 Token 报 `invalid_grant`？**
授权码一次性有效且 5 分钟过期；`code_verifier` 必须与授权请求的 `code_challenge` 匹配；
`redirect_uri` 必须与授权请求完全一致。

**Q：公共客户端为什么没有 refresh_token？**
框架默认不给 public client 签发 refresh token。请改用保密客户端（`client_secret_basic`）。

**Q：修改了 `sso.clients` 配置为什么不生效？**
客户端管理已迁移至 Web 管理页面 `/admin/clients`，不再通过 YML 配置。请以管理页面录入的客户端为准。

**Q：H2 与 MySQL 行为差异？**
测试在无 Docker 时回退 H2（MySQL 兼容模式）。生产请以 MySQL + Testcontainers 测试结果为准。

**Q：如何查看登录失败的具体原因？**
服务端日志（`com.mao.sso` 包，INFO 级别）记录失败原因（用户不存在/密码错误/禁用/锁定），前端只显示通用提示。
