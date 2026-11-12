package com.mao.sso.tools;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.cert.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * PEM 证书文件转 Java KeyStore（JKS / PKCS12），纯 Java 实现，无需 openssl / keytool。
 *
 * <h3>使用示例</h3>
 * <pre>{@code
 * // 1. 生成 truststore（验证服务器证书用）
 * CertificateConverter.builder()
 *         .caCert(Paths.get("D:/certs/mysql/ca.pem"))
 *         .output(Paths.get("D:/certs/mysql/truststore.p12"))
 *         .password("changeit")
 *         .buildTrustStore();
 *
 * // 2. 生成 keystore（双向认证用）
 * CertificateConverter.builder()
 *         .clientCert(Paths.get("D:/certs/mysql/client-cert.pem"))
 *         .clientKey(Paths.get("D:/certs/mysql/client-key.pem"))
 *         .output(Paths.get("D:/certs/mysql/client-keystore.p12"))
 *         .password("changeit")
 *         .buildKeyStore();
 * }</pre>
 *
 * 不用该工具类，可以使用命令行执行：
 * # 在 PowerShell 中执行，进入证书目录 D:/certs/mysql（证书不入库，apps 通过环境变量指向）
 * # 1. 生成 truststore（信任证书库，用于验证服务器）
 * keytool -importcert -alias MySQLCACert -file ca.pem -keystore truststore.jks -storepass maoappsso -noprompt
 * # 2. 如果要做双向认证，还需要生成 keystore（客户端身份证书）
 * # 先将 PEM 转 PKCS12
 * openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem -out client-keystore.p12 -name mysql-client -passout pass:maoappsso
 * 如果不行，报错，可能是Windows自带的keytool版本太老，openssl 默认的加密算法（通常是 AES-256-CBC 等较新的算法）解析不了，可以加兼容参数
 * openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem -out client-keystore.p12 -name mysql-client -passout pass:maoappsso -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES -macalg SHA1
 * # 再将 PKCS12 转 JKS
 * keytool -importkeystore -srckeystore client-keystore.p12 -srcstoretype PKCS12 -srcstorepass maoappsso -destkeystore client-keystore.jks -deststoretype JKS -deststorepass maoappsso
 */
public final class CertificateConverter {

    private static final String PEM_CERT_HEADER = "-----BEGIN CERTIFICATE-----";
    private static final String PEM_KEY_HEADER  = "-----BEGIN PRIVATE KEY-----";
    private static final String PEM_RSA_HEADER  = "-----BEGIN RSA PRIVATE KEY-----";

    private CertificateConverter() {}

    // ───────────────────────── Builder ─────────────────────────

    public static Builder builder() { return new Builder(); }

    public static final class Builder {
        private Path caCert;
        private Path clientCert;
        private Path clientKey;
        private Path output;
        private String password;
        private String keyStoreType = "PKCS12"; // JDK 9+ 默认 PKCS12，兼容性最好

        public Builder caCert(Path path)        { this.caCert = path; return this; }
        public Builder clientCert(Path path)    { this.clientCert = path; return this; }
        public Builder clientKey(Path path)     { this.clientKey = path; return this; }
        public Builder output(Path path)        { this.output = path; return this; }
        public Builder password(String pwd)     { this.password = pwd; return this; }
        public Builder keyStoreType(String type){ this.keyStoreType = type; return this; }

        /** 生成 truststore：只包含 CA 证书，用于验证服务器 */
        public void buildTrustStore() { new CertificateConverter().buildTrustStore(this); }
        /** 生成 keystore：包含客户端证书+私钥，用于双向认证 */
        public void buildKeyStore()   { new CertificateConverter().buildKeyStore(this); }
    }

    // ───────────────────────── 生成 truststore ─────────────────────────

    private void buildTrustStore(Builder b) {
        ensure(b.caCert != null, "caCert is required");
        ensure(b.output != null,   "output is required");
        ensure(b.password != null, "password is required");

        try {
            X509Certificate ca = readCert(b.caCert);
            KeyStore ts = KeyStore.getInstance(b.keyStoreType);
            ts.load(null, b.password.toCharArray());
            ts.setCertificateEntry("mysql-ca", ca);
            writeKeyStore(ts, b);
            System.out.println("✓ TrustStore written: " + b.output);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build truststore", e);
        }
    }

    // ───────────────────────── 生成 keystore ─────────────────────────

    private void buildKeyStore(Builder b) {
        ensure(b.clientCert != null, "clientCert is required");
        ensure(b.clientKey != null,  "clientKey is required");
        ensure(b.output != null,     "output is required");
        ensure(b.password != null,   "password is required");

        try {
            X509Certificate cert = readCert(b.clientCert);
            PrivateKey key = readPrivateKey(b.clientKey);

            // 重建证书链（client-cert 由 CA 签发）
            X509Certificate[] chain;
            if (b.caCert != null) {
                chain = new X509Certificate[] { cert, readCert(b.caCert) };
            } else {
                chain = new X509Certificate[] { cert };
            }

            KeyStore ks = KeyStore.getInstance(b.keyStoreType);
            ks.load(null, b.password.toCharArray());
            ks.setKeyEntry("mysql-client", key, b.password.toCharArray(), chain);
            writeKeyStore(ks, b);
            System.out.println("✓ KeyStore written: " + b.output);
        } catch (Exception e) {
            throw new RuntimeException("Failed to build keystore", e);
        }
    }

    // ───────────────────────── PEM 解析 ─────────────────────────

    /** 读取 PEM 格式的 X.509 证书 */
    private X509Certificate readCert(Path path) throws Exception {
        byte[] der = pemDecode(Files.readString(path), PEM_CERT_HEADER);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
    }

    /** 读取 PEM 格式的私钥（支持 PKCS#8 和 PKCS#1 RSA） */
    private PrivateKey readPrivateKey(Path path) throws Exception {
        String content = Files.readString(path);

        // PKCS#8: -----BEGIN PRIVATE KEY-----
        if (content.contains(PEM_KEY_HEADER)) {
            byte[] der = pemDecode(content, PEM_KEY_HEADER);
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new PKCS8EncodedKeySpec(der));
        }

        // PKCS#1: -----BEGIN RSA PRIVATE KEY-----
        if (content.contains(PEM_RSA_HEADER)) {
            byte[] der = pemDecode(content, PEM_RSA_HEADER);
            // PKCS#1 RSAPrivateKey 结构还需要转换
            return pkcs1ToPkcs8(der);
        }

        throw new IllegalArgumentException("Unsupported private key format in: " + path);
    }

    // ───────────────────────── 工具方法 ─────────────────────────

    /** PEM base64 解码：去掉头尾标记和换行，返回 DER 字节 */
    private byte[] pemDecode(String pem, String header) {
        int start = pem.indexOf(header);
        if (start < 0) throw new IllegalArgumentException("Missing header: " + header);
        String footer = header.replace("BEGIN", "END");
        int end = pem.indexOf(footer, start);
        if (end < 0) throw new IllegalArgumentException("Missing footer: " + footer);
        String base64 = pem.substring(start + header.length(), end)
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    /**
     * PKCS#1 RSAPrivateKey → PKCS#8 PrivateKeyInfo。
     * PKCS#1 结构：SEQUENCE { INTEGER(0), N, E, D, P, Q, DP, DQ, QINV }
     * PKCS#8 结构：SEQUENCE { INTEGER(0), AlgorithmIdentifier, OCTET STRING(PKCS#1) }
     */
    private PrivateKey pkcs1ToPkcs8(byte[] pkcs1) throws Exception {
        // PKCS#8 固定前缀：SEQUENCE + AlgorithmIdentifier(rsaEncryption) + OCTET STRING
        byte[] rsaOid = new byte[] {
            0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D,
            0x01, 0x01, 0x01, 0x05, 0x00
        };
        // PKCS#8 wrapper
        ByteArrayOutputStream pkcs8 = new ByteArrayOutputStream();
        pkcs8.write(0x30); // SEQUENCE
        writeLength(pkcs8, 3 + rsaOid.length + 4 + pkcs1.length);
        pkcs8.write(0x02); pkcs8.write(0x01); pkcs8.write(0x00); // version
        pkcs8.write(0x30); // AlgorithmIdentifier SEQUENCE
        writeLength(pkcs8, rsaOid.length);
        pkcs8.write(rsaOid);
        pkcs8.write(0x04); // OCTET STRING
        writeLength(pkcs8, pkcs1.length);
        pkcs8.write(pkcs1);

        return KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8.toByteArray()));
    }

    /** ASN.1 DER 长度编码 */
    private void writeLength(ByteArrayOutputStream out, int len) {
        if (len < 128) {
            out.write(len);
        } else {
            byte[] bytes = new byte[4];
            int pos = 0;
            while (len > 0) { bytes[pos++] = (byte) (len & 0xFF); len >>= 8; }
            out.write(0x80 | pos);
            for (int i = pos - 1; i >= 0; i--) out.write(bytes[i]);
        }
    }

    /** 写入 KeyStore 到文件 */
    private void writeKeyStore(KeyStore ks, Builder b) throws Exception {
        Files.createDirectories(b.output.getParent());
        try (OutputStream os = Files.newOutputStream(b.output)) {
            ks.store(os, b.password.toCharArray());
        }
    }

    private void ensure(boolean condition, String msg) {
        if (!condition) throw new IllegalArgumentException(msg);
    }

    // ───────────────────────── main（独立测试入口） ─────────────────────────

    public static void main(String[] args) {
        // 证书不放在仓库里：pem 与 p12 统一放在本机目录，由 application.yml 的
        // SSO_DB_TRUSTSTORE_URL / SSO_DB_KEYSTORE_URL 指向
        Path certsDir = Paths.get("D:/certs/mysql");

        // 1. 生成 truststore
        builder()
                .caCert(certsDir.resolve("ca.pem"))
                .output(certsDir.resolve("truststore.p12"))
                .password("maoappsso")
                .buildTrustStore();

        // 2. 生成 keystore
        builder()
                .clientCert(certsDir.resolve("client-cert.pem"))
                .clientKey(certsDir.resolve("client-key.pem"))
                .caCert(certsDir.resolve("ca.pem"))
                .output(certsDir.resolve("client-keystore.p12"))
                .password("maoappsso")
                .buildKeyStore();
    }
}