-- V4: OAuth2 Authorization Consent 表
-- 结构完全复用 Spring Authorization Server 官方 schema
-- (org.springframework.security.oauth2.server.authorization.oauth2-authorization-consent-schema.sql)
CREATE TABLE oauth2_authorization_consent (
    registered_client_id varchar(100) NOT NULL,
    principal_name varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name)
);
