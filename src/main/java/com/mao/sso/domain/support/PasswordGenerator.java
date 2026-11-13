package com.mao.sso.domain.support;

import java.security.SecureRandom;

/**
 * 随机密码生成器（用于「管理员创建用户」与「重置密码」）。
 *
 * <p>策略：长度 16，至少各含一个大写、小写、数字与符号；剔除易混淆字符（0/O/o、1/l/I）。</p>
 *
 * <p>明文仅在生成时返回一次，服务端只保存 Argon2id 哈希，无法找回。</p>
 */
public final class PasswordGenerator {

	private static final String UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ";

	private static final String LOWER = "abcdefghijkmnopqrstuvwxyz";

	private static final String DIGITS = "23456789";

	private static final String SYMBOLS = "!@#$%^&*-_=+?";

	private static final String ALL = UPPER + LOWER + DIGITS + SYMBOLS;

	private static final int LENGTH = 16;

	private static final SecureRandom RANDOM = new SecureRandom();

	private PasswordGenerator() {
	}

	public static String generate() {
		char[] password = new char[LENGTH];
		password[0] = pick(UPPER);
		password[1] = pick(LOWER);
		password[2] = pick(DIGITS);
		password[3] = pick(SYMBOLS);
		for (int i = 4; i < LENGTH; i++) {
			password[i] = pick(ALL);
		}
		// Fisher-Yates 洗牌，避免固定位置规律
		for (int i = LENGTH - 1; i > 0; i--) {
			int j = RANDOM.nextInt(i + 1);
			char temp = password[i];
			password[i] = password[j];
			password[j] = temp;
		}
		return new String(password);
	}

	private static char pick(String source) {
		return source.charAt(RANDOM.nextInt(source.length()));
	}

}
