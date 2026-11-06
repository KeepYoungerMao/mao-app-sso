-- V1: 用户体系表结构（users / roles / user_roles）
-- 兼容 MySQL 8.0+ 与 H2(MySQL 兼容模式，用于无 Docker 的测试环境)
-- 不存储明文密码：password_hash 仅保存 Argon2id 哈希值

CREATE TABLE roles (
    id          BIGINT AUTO_INCREMENT PRIMARY KEY,
    code        VARCHAR(50)  NOT NULL,
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uk_roles_code UNIQUE (code)
);

CREATE TABLE users (
    id                 BIGINT AUTO_INCREMENT PRIMARY KEY,
    username           VARCHAR(50)  NOT NULL,
    email              VARCHAR(255) NOT NULL,
    password_hash      VARCHAR(255) NOT NULL,
    display_name       VARCHAR(100) NOT NULL,
    enabled            BOOLEAN      NOT NULL DEFAULT TRUE,
    account_locked     BOOLEAN      NOT NULL DEFAULT FALSE,
    account_expired    BOOLEAN      NOT NULL DEFAULT FALSE,
    credentials_expired BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at         TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uk_users_username UNIQUE (username),
    CONSTRAINT uk_users_email UNIQUE (email)
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE INDEX idx_user_roles_role_id ON user_roles (role_id);

-- 预置角色（幂等由 Flyway 版本化脚本本身保证；运行期不再重复插入）
INSERT INTO roles (code, name, description) VALUES
    ('ROLE_USER', '普通用户', '已认证的普通用户'),
    ('ROLE_ADMIN', '管理员', '系统管理员，拥有全部权限');
