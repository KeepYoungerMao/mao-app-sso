-- V1: OAuth2 客户端与授权表 + 默认管理控制台客户端
--
-- 三张表结构完全复用 Spring Authorization Server 官方 schema：
--   oauth2-registered-client-schema.sql
--   oauth2-authorization-schema.sql
--   oauth2-authorization-consent-schema.sql
-- 差异仅有两处（均为追加，不改动官方列）：
--   1. oauth2_registered_client 追加审计列 created_by / created_at / updated_by / updated_at
--      （官方 JDBC 实现不负责审计字段，由应用层写入）
--   2. 为 client_id 建唯一索引（逻辑上必须唯一，官方脚本未显式约束）
--
-- 预置客户端 mao-app-admin：管理控制台使用的公共客户端（public client）
--   * 认证方式 none，强制 PKCE（require-proof-key = true）
--   * 仅两个 scope：openid / profile
--   * 环境无前端域名时先给本地开发默认回调，上线前通过
--     POST /api/v1/admin/client/update 改成控制台实际地址

CREATE TABLE oauth2_registered_client (
    id varchar(100) NOT NULL,
    client_id varchar(100) NOT NULL,
    client_id_issued_at timestamp DEFAULT CURRENT_TIMESTAMP NOT NULL,
    client_secret varchar(200) DEFAULT NULL,
    client_secret_expires_at timestamp DEFAULT NULL,
    client_name varchar(200) NOT NULL,
    client_authentication_methods varchar(1000) NOT NULL,
    authorization_grant_types varchar(1000) NOT NULL,
    redirect_uris varchar(1000) DEFAULT NULL,
    post_logout_redirect_uris varchar(1000) DEFAULT NULL,
    scopes varchar(1000) NOT NULL,
    client_settings varchar(2000) NOT NULL,
    token_settings varchar(2000) NOT NULL,
    created_by VARCHAR(50) NOT NULL DEFAULT 'system',
    created_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_by VARCHAR(50) NOT NULL DEFAULT 'system',
    updated_at TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX uk_oauth2_registered_client_client_id ON oauth2_registered_client (client_id);

CREATE TABLE oauth2_authorization (
    id varchar(100) NOT NULL,
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorization_grant_type varchar(100) NOT NULL,
    authorized_scopes varchar(1000) DEFAULT NULL,
    attributes blob DEFAULT NULL,
    state varchar(500) DEFAULT NULL,
    authorization_code_value blob DEFAULT NULL,
    authorization_code_issued_at timestamp DEFAULT NULL,
    authorization_code_expires_at timestamp DEFAULT NULL,
    authorization_code_metadata blob DEFAULT NULL,
    access_token_value blob DEFAULT NULL,
    access_token_issued_at timestamp DEFAULT NULL,
    access_token_expires_at timestamp DEFAULT NULL,
    access_token_metadata blob DEFAULT NULL,
    access_token_type varchar(100) DEFAULT NULL,
    access_token_scopes varchar(1000) DEFAULT NULL,
    oidc_id_token_value blob DEFAULT NULL,
    oidc_id_token_issued_at timestamp DEFAULT NULL,
    oidc_id_token_expires_at timestamp DEFAULT NULL,
    oidc_id_token_metadata blob DEFAULT NULL,
    refresh_token_value blob DEFAULT NULL,
    refresh_token_issued_at timestamp DEFAULT NULL,
    refresh_token_expires_at timestamp DEFAULT NULL,
    refresh_token_metadata blob DEFAULT NULL,
    user_code_value blob DEFAULT NULL,
    user_code_issued_at timestamp DEFAULT NULL,
    user_code_expires_at timestamp DEFAULT NULL,
    user_code_metadata blob DEFAULT NULL,
    device_code_value blob DEFAULT NULL,
    device_code_issued_at timestamp DEFAULT NULL,
    device_code_expires_at timestamp DEFAULT NULL,
    device_code_metadata blob DEFAULT NULL,
    PRIMARY KEY (id)
);

CREATE INDEX idx_oauth2_authorization_client_id ON oauth2_authorization (registered_client_id);
CREATE INDEX idx_oauth2_authorization_principal_name ON oauth2_authorization (principal_name);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);

-- ---------- 默认客户端：管理控制台 ----------
-- 列格式必须与 SAS 官方 JdbcRegisteredClientRepository 一致：
--   client_authentication_methods / authorization_grant_types / redirect_uris /
--   post_logout_redirect_uris / scopes 都是**逗号分隔**字符串（不是 JSON 数组）；
--   只有 client_settings / token_settings 是 JSON，且必须带
--   "@class":"java.util.Collections$UnmodifiableMap" —— SAS 用开启多态类型校验的
--   ObjectMapper 反序列化这两列，缺少 @class 会抛 missing type id property '@class'。
--
-- 项目约定：**一个客户端只允许一个 redirect_uri**，因此 redirect_uris 只有一条。
-- 前端换端口时请用 POST /api/v1/admin/client/update 改这一条，不要再追加第二个地址
-- （追加会破坏 DCR 按回调反查客户端的唯一性）。post_logout_redirect_uris 是
-- OIDC 登出回调，属独立概念、不受该约定限制，这里与登录入口保持一致。
INSERT INTO oauth2_registered_client (id, client_id, client_id_issued_at, client_secret,
                                      client_secret_expires_at, client_name,
                                      client_authentication_methods, authorization_grant_types,
                                      redirect_uris, post_logout_redirect_uris, scopes,
                                      client_settings, token_settings,
                                      created_by, updated_by)
VALUES ('mao-app-admin', 'mao-app-admin', CURRENT_TIMESTAMP, NULL, NULL, '管理控制台',
        'none',
        'authorization_code,refresh_token',
        'http://localhost:5173/callback',
        'http://localhost:5173/',
        'openid,profile',
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":false}',
        '{"@class":"java.util.Collections$UnmodifiableMap","settings.token.authorization-code-time-to-live":"PT5M","settings.token.access-token-time-to-live":"PT15M","settings.token.refresh-token-time-to-live":"P30D","settings.token.reuse-refresh-tokens":false,"settings.token.id-token-signature-algorithm":"RS256"}',
        'system', 'system');
