-- V2: 用户与角色表 + 默认角色 / 默认管理员
--
-- 设计要点：
--   * 主键统一 INT AUTO_INCREMENT（业务表），OAuth 表仍用官方 varchar(100)
--   * 密码过期用 credentials_expired_at 单一来源表达（NULL = 永不过期），
--     不再保留布尔列，是否过期由应用层按当前时间派生
--   * 审计字段 created_by / updated_by 由应用层写入（AuditContext），
--     不再依赖 JPA Auditing
--   * 不存明文密码：password_hash 仅存 Argon2id 哈希
--
-- 预置数据：
--   角色 admin / customer
--   用户 admin（绑定 admin 角色），初始密码 Admin@123456，must_change_password = TRUE
--   —— 首次登录后必须立即修改密码；也可用环境变量 SSO_ADMIN_PASSWORD 在启动时覆盖，
--      见 UserInitializer。

CREATE TABLE roles (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    code        VARCHAR(50)  NOT NULL,
    name        VARCHAR(100) NOT NULL,
    description VARCHAR(255),
    created_by  VARCHAR(50)  NOT NULL DEFAULT 'system',
    updated_by  VARCHAR(50)  NOT NULL DEFAULT 'system',
    created_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at  TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uk_roles_code UNIQUE (code)
);

CREATE TABLE users (
    id                    INT AUTO_INCREMENT PRIMARY KEY,
    username              VARCHAR(50)  NOT NULL,
    email                 VARCHAR(255) NOT NULL,
    phone                 VARCHAR(32)  NULL,
    avatar                VARCHAR(500) NULL,
    password_hash         VARCHAR(255) NOT NULL,
    display_name          VARCHAR(100) NOT NULL,
    enabled               BOOLEAN      NOT NULL DEFAULT TRUE,
    account_locked        BOOLEAN      NOT NULL DEFAULT FALSE,
    account_expired       BOOLEAN      NOT NULL DEFAULT FALSE,
    last_login_at         TIMESTAMP(6) NULL,
    must_change_password  BOOLEAN      NOT NULL DEFAULT FALSE,
    credentials_expired_at TIMESTAMP(6) NULL,
    created_by            VARCHAR(50)  NOT NULL DEFAULT 'system',
    updated_by            VARCHAR(50)  NOT NULL DEFAULT 'system',
    created_at            TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at            TIMESTAMP(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uk_users_username UNIQUE (username),
    CONSTRAINT uk_users_email UNIQUE (email)
);

CREATE INDEX idx_users_created_at ON users (created_at);

CREATE TABLE user_roles (
    user_id INT NOT NULL,
    role_id INT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles (id) ON DELETE CASCADE
);

CREATE INDEX idx_user_roles_role_id ON user_roles (role_id);

-- ---------- 默认角色 ----------
-- 角色 code 直接作为业务标识（小写），Spring Security 侧统一映射为 ROLE_<大写>：
--   admin    → ROLE_ADMIN
--   customer → ROLE_CUSTOMER
-- scopes 不参与权限控制，接口授权一律基于角色。
INSERT INTO roles (code, name, description, created_by, updated_by) VALUES
    ('admin', '管理员', '系统管理员，可访问管理 API', 'system', 'system'),
    ('customer', '客户', '普通业务用户，仅可登录与自助维护资料', 'system', 'system');

-- ---------- 默认管理员 ----------
-- 密码为 Admin@123456 的 Argon2id 哈希（m=19456, t=2, p=1, salt=16B, hash=32B），
-- must_change_password = TRUE 强制首次登录后修改。
INSERT INTO users (username, email, password_hash, display_name, enabled, account_locked,
                   account_expired, must_change_password, created_by, updated_by)
VALUES ('admin', 'admin@mao.local',
        '$argon2id$v=19$m=19456,t=2,p=1$Wvm21Zv6joI2xb7u9Fh59Q$Ibibmeb2H2vNUfUn0H/nmytWj6jhwRK/a/KegIkFxJo',
        '系统管理员', TRUE, FALSE, FALSE, TRUE, 'system', 'system');

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r WHERE u.username = 'admin' AND r.code = 'admin';
