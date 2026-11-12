package com.mao.sso.user;

/**
 * 管理员创建/重置用户后的返回值：明文密码只在此处出现一次。
 *
 * @param id 用户主键
 * @param username 用户名
 * @param rawPassword 明文密码（服务端不保存，无法找回）
 */
public record CreatedUser(Integer id, String username, String rawPassword) {
}
