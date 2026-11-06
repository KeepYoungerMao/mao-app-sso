package com.mao.sso.tools;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * 生产环境 JWK Set 生成工具（开发/运维辅助，不属于应用运行时组件）。
 *
 * <p>生成包含 RSA 私钥的 JWK Set JSON 文件，供 {@code sso.jwk.location} 配置使用。
 * 生成后必须限制文件权限（仅应用进程可读），并纳入密钥管理流程。</p>
 *
 * <h3>使用方式</h3>
 * <pre>
 * mvn -q dependency:build-classpath -Dmdep.outputFile=target/cp.txt
 * java -cp "target/classes;$(cat target/cp.txt)" com.mao.sso.tools.JwkGenerator ./jwk.json [keyId]
 * </pre>
 *
 * <p>密钥轮换：生成包含新旧两个密钥的 JWK Set（均带 kid），
 * JWKS 端点会公开全部公钥，签名默认使用第一个密钥；轮换时调整顺序即可。</p>
 */
public final class JwkGenerator {

	private JwkGenerator() {
	}

	public static void main(String[] args) throws Exception {
		String outputPath = (args.length > 0) ? args[0] : "jwk.json";
		String keyId = (args.length > 1) ? args[1] : UUID.randomUUID().toString();

		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID(keyId)
			.build();

		// 注意：Nimbus 的 toString(boolean) 参数为 publicOnly，false 才会输出私钥
		String json = new JWKSet(rsaKey).toString(false);
		Path path = Paths.get(outputPath);
		Files.writeString(path, json, StandardCharsets.UTF_8);

		System.out.println("已生成 JWK Set: " + path.toAbsolutePath());
		System.out.println("keyId (kid): " + keyId);
		System.out.println("请配置环境变量：SSO_JWK_LOCATION=" + path.toAbsolutePath());
		System.out.println("警告：该文件包含签名私钥，请限制文件访问权限并纳入密钥管理流程。");
	}

}
