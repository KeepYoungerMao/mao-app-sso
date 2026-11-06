package com.mao.sso.oauth;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 动态客户端注册的按 IP 限流器（固定窗口，1 分钟）。
 *
 * <p>仅做频率保护（防止单 IP 暴力探测预录入列表），不再与白名单策略耦合。</p>
 */
public final class DcrRateLimiter {

	private static final Logger log = LoggerFactory.getLogger(DcrRateLimiter.class);

	private static final long WINDOW_MILLIS = 60_000L;

	private final int limitPerMinute;

	private final Map<String, Window> windows = new ConcurrentHashMap<>();

	public DcrRateLimiter(int limitPerMinute) {
		this.limitPerMinute = limitPerMinute;
	}

	/** 判定当前请求是否允许注册；超限抛出 {@link DcrRejectedException}。 */
	public void check() {
		if (this.limitPerMinute <= 0) {
			return;
		}
		String clientKey = resolveClientKey();
		long currentWindow = System.currentTimeMillis() / WINDOW_MILLIS;
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
		purgeExpired(currentWindow);
	}

	private void purgeExpired(long currentWindow) {
		if (this.windows.size() < 128) {
			return;
		}
		this.windows.entrySet().removeIf((entry) -> entry.getValue().startedWindow < currentWindow);
	}

	private static String resolveClientKey() {
		if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
			String remoteAddress = attributes.getRequest().getRemoteAddr();
			if (remoteAddress != null && !remoteAddress.isBlank()) {
				return remoteAddress;
			}
		}
		return "unknown";
	}

	private static final class Window {

		private long startedWindow;

		private final AtomicInteger count = new AtomicInteger();

		private Window(long startedWindow) {
			this.startedWindow = startedWindow;
		}

	}

}
