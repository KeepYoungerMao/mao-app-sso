package com.mao.sso.tools;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
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
 * <p>生成包含 RSA 私钥的 JWK Set JSON，供 {@code sso.jwk.location}（环境变量
 * {@code SSO_JWK_LOCATION}）加载。输出位置固定为 {@link #OUTPUT_FILE}，
 * <b>每次执行都会先删除旧文件再重建</b>，因此每次运行都会产生一对新密钥。</p>
 *
 * <h3>使用方式</h3>
 * <pre>
 * mvn -q -o compile
 * mvn -q -o dependency:build-classpath -Dmdep.outputFile=target/cp.txt
 * java -cp "target/classes;$(cat target/cp.txt)" com.mao.sso.tools.JwkGenerator
 * </pre>
 *
 * <p>不需要任何命令行参数：输出路径与密钥长度都是本类中的常量。换机器或换操作系统时
 * 只需修改 {@link #OUTPUT_FILE}（这里的路径是本机 Windows 约定，Linux 可改成
 * {@code /etc/mao-sso/}）。</p>
 *
 * <h3>注意</h3>
 * <ul>
 *   <li>文件是<b>明文</b>，含 RSA 私钥全部 CRT 参数，泄露即可伪造任意用户 Token；
 *       请限制文件权限，不要提交到版本库。</li>
 *   <li>因为会覆盖旧文件，所以它<b>不是</b>密钥轮换工具。需要平滑轮换时，
 *       手工构造包含新旧两把密钥（不同 kid）的 JWK Set，签名使用第一把。</li>
 * </ul>
 */
public final class JwkGenerator {

	/** 输出目录（本机固定路径，不接受命令行参数覆盖）。 */
	private static final Path OUTPUT_DIR = Path.of("D:/certs/sso-jwk");

	/** 输出文件名，{@code SSO_JWK_LOCATION} 指向这里。 */
	private static final String OUTPUT_FILENAME = "jwk-set.json";

	private static final Path OUTPUT_FILE = OUTPUT_DIR.resolve(OUTPUT_FILENAME);

	/** RSA 密钥长度（2048 位足够 RS256，且客户端验签开销可忽略）。 */
	private static final int KEY_SIZE = 2048;

	private JwkGenerator() {
	}

	/**
	 * 入口。<b>签名不能省 `String[]`、不能去掉 public</b>：JVM 只认
	 * {@code public static void main(String[])}，写成无参形式 IDEA 会报"找不到 main 方法"。
	 * 这里的 args 不读取——输出路径、密钥长度全部是类内常量。
	 */
	public static void main(String[] args) throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(KEY_SIZE);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();

		String keyId = UUID.randomUUID().toString();
		RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
			.privateKey((RSAPrivateKey) keyPair.getPrivate())
			.keyID(keyId)
			.build();

		// 注意：Nimbus 的 toString(boolean) 参数为 publicOnly，false 才会输出私钥
		String json = new JWKSet(rsaKey).toString(false);

		Files.createDirectories(OUTPUT_DIR);
		// 先删除再写：避免旧密钥残留，也防止遗留文件被误认为本次生成结果
		Files.deleteIfExists(OUTPUT_FILE);
		Files.writeString(OUTPUT_FILE, json, StandardCharsets.UTF_8);

		// 提示里统一用正斜杠：Windows 下的反斜杠在 file: 伪 URL 里容易被误解析
		String location = OUTPUT_FILE.toAbsolutePath().toString().replace('\\', '/');

		System.out.println("已生成 JWK Set: " + OUTPUT_FILE.toAbsolutePath());
		System.out.println("文件大小: " + Files.size(OUTPUT_FILE) + " 字节");
		System.out.println("keyId (kid): " + keyId);
		System.out.println();
		System.out.println("启动时配置：");
		System.out.println("  本地：application.yml 已指向 file:" + location + "，无需额外配置");
		System.out.println("  生产：在 jar 同级 config/application.yml 里写 sso.jwk.location: file:" + location);
		System.out.println("        （并把 sso.jwk.allow-ephemeral 设为 false）");
		System.out.println();
		System.out.println("警告：该文件包含签名私钥，请限制文件访问权限，且不要提交到版本库。");
	}

}
