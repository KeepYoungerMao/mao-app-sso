package com.mao.sso.auth.dcr;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 动态客户端注册的按客户端 IP 限流器（固定窗口，1 分钟）。
 *
 * <p>仅做频率保护（防止单 IP 暴力探测预录入列表），不再与白名单策略耦合。</p>
 *
 * <h3>为什么不能直接用 {@code getRemoteAddr()}</h3>
 * <p>应用部署在 Nginx / ALB / K8s Ingress 之后时，{@code getRemoteAddr()} 返回的是<b>代理的地址</b>。
 * 直接拿它当限流键，所有客户端会共用同一个窗口配额 —— 单个扫描器打满 30 次，就能让这一分钟内
 * 所有正常客户端的注册全部失败。这不是安全问题，是部署在代理后必然踩到的可用性问题。</p>
 *
 * <h3>取值规则</h3>
 * <ol>
 *   <li><b>直连</b>（对端是公网地址）→ 用 {@code remoteAddr}，<b>不读</b>任何转发头。
 *       客户端自己能设置 {@code X-Forwarded-For}，直连场景信任它等于给出绕过限流的开关。</li>
 *   <li><b>经代理</b>（对端是回环/内网地址）→ 从 {@code X-Forwarded-For} <b>右往左</b>取第一个
 *       非内网地址。客户端伪造的值会被代理追加的真实地址挤到左边，所以从右往左才是对的；
 *       {@code X-Real-IP} 作为兜底。</li>
 * </ol>
 *
 * <p>该算法与 Tomcat 的 {@code RemoteIpValve}（{@code server.forward-headers-strategy=native}）
 * 等价。若日后启用该配置，{@code remoteAddr} 已是真实客户端地址，规则 1 直接命中，行为不变；
 * 两套机制可以共存，不会互相破坏。</p>
 */
public final class DcrRateLimiter {

	private static final Logger log = LoggerFactory.getLogger(DcrRateLimiter.class);

	private static final long WINDOW_MILLIS = 60_000L;

	/** 窗口表跟踪的客户端上限：防止伪造大量来源地址把内存撑爆。 */
	private static final int MAX_TRACKED_CLIENTS = 10_000;

	/** 超过上限后的共享桶，按整体配额限流（宁可整体偏严，也不无限增长）。 */
	private static final String OVERFLOW_KEY = "__overflow__";

	/** 过期清理的最小间隔，避免每个请求都做一次 O(n) 扫描。 */
	private static final long PURGE_INTERVAL_MILLIS = 1_000L;

	private final int limitPerMinute;

	private final Map<String, Window> windows = new ConcurrentHashMap<>();

	/** 时间源，测试可注入固定时钟以获得确定性。 */
	private final java.util.function.LongSupplier clock;

	private volatile long lastPurgeMillis;

	public DcrRateLimiter(int limitPerMinute) {
		this(limitPerMinute, System::currentTimeMillis);
	}

	DcrRateLimiter(int limitPerMinute, java.util.function.LongSupplier clock) {
		this.limitPerMinute = limitPerMinute;
		this.clock = clock;
	}

	/** 判定当前请求是否允许注册；超限抛出 {@link DcrRejectedException}。 */
	public void check() {
		if (this.limitPerMinute <= 0) {
			return;
		}
		String clientKey = resolveClientKey();
		if (this.windows.size() >= MAX_TRACKED_CLIENTS && !this.windows.containsKey(clientKey)) {
			clientKey = OVERFLOW_KEY;
		}
		long now = this.clock.getAsLong();
		long currentWindow = now / WINDOW_MILLIS;
		Window window = this.windows.computeIfAbsent(clientKey, (key) -> new Window(currentWindow));
		if (window.startedWindow != currentWindow) {
			synchronized (window) {
				if (window.startedWindow != currentWindow) {
					window.startedWindow = currentWindow;
					window.count.set(0);
				}
			}
		}
		int current = window.count.incrementAndGet();
		if (current > this.limitPerMinute) {
			log.warn("动态客户端注册被限流: clientKey={} limit={}/min", clientKey, this.limitPerMinute);
			throw new DcrRejectedException("invalid_request",
					"注册过于频繁：单 IP 每分钟最多 " + this.limitPerMinute + " 次客户端注册，请稍后重试");
		}
		purgeExpired(currentWindow, now);
	}

	private void purgeExpired(long currentWindow, long now) {
		if (this.windows.size() < 128) {
			return;
		}
		if (now - this.lastPurgeMillis < PURGE_INTERVAL_MILLIS) {
			return;
		}
		this.lastPurgeMillis = now;
		this.windows.entrySet().removeIf((entry) -> entry.getValue().startedWindow < currentWindow);
	}

	// ---------- 客户端标识 ----------

	private static String resolveClientKey() {
		if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes)) {
			return "unknown";
		}
		String remoteAddress = attributes.getRequest().getRemoteAddr();
		// 直连：对端就是客户端本身，只认它，不信任可被伪造的转发头
		if (isPublicAddress(remoteAddress)) {
			return remoteAddress;
		}
		// 代理后：转发链从右往左第一个公网地址才是真实客户端
		String forwarded = rightmostPublicAddress(attributes.getRequest().getHeader("X-Forwarded-For"));
		if (forwarded != null) {
			return forwarded;
		}
		String realIp = attributes.getRequest().getHeader("X-Real-IP");
		if (realIp != null && !realIp.isBlank()) {
			return realIp.trim();
		}
		return (remoteAddress != null && !remoteAddress.isBlank()) ? remoteAddress : "unknown";
	}

	private static String rightmostPublicAddress(String header) {
		if (header == null || header.isBlank()) {
			return null;
		}
		String[] parts = header.split(",");
		for (int i = parts.length - 1; i >= 0; i--) {
			String candidate = parts[i].trim();
			if (!candidate.isEmpty() && isPublicAddress(candidate)) {
				return candidate;
			}
		}
		return null;
	}

	/**
	 * 判断是否为可路由的公网地址。
	 *
	 * <p>解析失败、空值、回环、私有段、链路本地一律视为「非公网」，这样处理是偏保守的：
	 * 拿不准时继续往左找，最终兜底到 {@code remoteAddr}。</p>
	 */
	private static boolean isPublicAddress(String address) {
		String value = normalize(address);
		if (value == null) {
			return false;
		}
		if (value.indexOf(':') >= 0) {
			String lower = value.toLowerCase();
			return !(lower.equals("::1") || lower.equals("::") || lower.startsWith("fe80:")
					|| lower.startsWith("fc") || lower.startsWith("fd") || lower.startsWith("::ffff:127."));
		}
		String[] octets = value.split("\\.");
		if (octets.length != 4) {
			return false;
		}
		int first;
		int second;
		try {
			first = Integer.parseInt(octets[0]);
			second = Integer.parseInt(octets[1]);
		}
		catch (NumberFormatException ex) {
			return false;
		}
		if (first == 0 || first == 10 || first == 127) {
			return false;
		}
		if (first == 172 && second >= 16 && second <= 31) {
			return false;
		}
		if (first == 192 && second == 168) {
			return false;
		}
		if (first == 169 && second == 254) {
			return false;
		}
		return true;
	}

	/** 去掉 IPv6 的方括号与 IPv4 的端口后缀，返回纯地址；无法识别时返回 null。 */
	private static String normalize(String address) {
		if (address == null || address.isBlank()) {
			return null;
		}
		String value = address.trim();
		if (value.startsWith("[")) {
			int end = value.indexOf(']');
			return (end > 1) ? value.substring(1, end) : null;
		}
		int firstColon = value.indexOf(':');
		if (firstColon >= 0 && firstColon == value.lastIndexOf(':')) {
			// 单冒号：IPv4:port
			return value.substring(0, firstColon);
		}
		return value;
	}

	private static final class Window {

		private long startedWindow;

		private final AtomicInteger count = new AtomicInteger();

		private Window(long startedWindow) {
			this.startedWindow = startedWindow;
		}

	}

}
