-- V2: OAuth2 Registered Client 表
-- 结构完全复用 Spring Authorization Server 官方 schema
-- (org.springframework.security.oauth2.server.authorization.client.oauth2-registered-client-schema.sql)
-- 补充：client_id 唯一索引（逻辑上必须唯一，官方 schema 未显式约束）
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
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX uk_oauth2_registered_client_client_id ON oauth2_registered_client (client_id);
