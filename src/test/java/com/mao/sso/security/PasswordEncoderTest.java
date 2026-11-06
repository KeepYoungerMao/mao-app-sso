package com.mao.sso.security;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 密码编码器测试：验证 Argon2id 算法、加盐、无常明文泄漏。
 */
class PasswordEncoderTest {

	private final PasswordEncoder encoder = new Argon2PasswordEncoder(16, 32, 1, 19456, 2);

	@Test
	@DisplayName("编码后可校验原密码")
	void encodesAndMatchesRawPassword() {
		String hash = encoder.encode("CorrectHorse9!");
		assertThat(encoder.matches("CorrectHorse9!", hash)).isTrue();
	}

	@Test
	@DisplayName("哈希值不是明文")
	void hashIsNotPlaintext() {
		String raw = "CorrectHorse9!";
		String hash = encoder.encode(raw);
		assertThat(hash).isNotEqualTo(raw);
		assertThat(hash).doesNotContain(raw);
	}

	@Test
	@DisplayName("错误密码校验失败")
	void wrongPasswordDoesNotMatch() {
		String hash = encoder.encode("CorrectHorse9!");
		assertThat(encoder.matches("wrong-password", hash)).isFalse();
	}

	@Test
	@DisplayName("相同密码生成不同哈希（随机盐）")
	void samePasswordProducesDifferentHashes() {
		assertThat(encoder.encode("same-password")).isNotEqualTo(encoder.encode("same-password"));
	}

	@Test
	@DisplayName("使用 Argon2id 算法编码")
	void usesArgon2idAlgorithm() {
		String hash = encoder.encode("secret");
		assertThat(hash).startsWith("$argon2id$v=19$");
	}

	@Test
	@DisplayName("与 PasswordEncoderConfig 中的参数一致")
	void matchesConfiguredParameters() {
		PasswordEncoder configured = new com.mao.sso.security.PasswordEncoderConfig().passwordEncoder();
		String hash = configured.encode("Passw0rd!");
		assertThat(configured.matches("Passw0rd!", hash)).isTrue();
		assertThat(this.encoder.matches("Passw0rd!", hash)).isTrue();
	}

}
