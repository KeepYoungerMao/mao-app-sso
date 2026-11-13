package com.mao.sso.auth.dcr;

import java.util.concurrent.atomic.AtomicLong;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * {@link DcrRateLimiter} 的客户端识别与限流行为。
 *
 * <p>核心回归点：应用部署在反向代理之后时，{@code getRemoteAddr()} 拿到的是代理地址，
 * 若直接当限流键，所有客户端会共用一份配额 —— 一个扫描器即可打满全局限额。</p>
 */
class DcrRateLimiterTest {

	private final AtomicLong now = new AtomicLong(1_700_000_000_000L);

	@AfterEach
	void clearRequestContext() {
		RequestContextHolder.resetRequestAttributes();
	}

	private DcrRateLimiter limiter(int limitPerMinute) {
		return new DcrRateLimiter(limitPerMinute, this.now::get);
	}

	private static void requestFrom(String remoteAddr, String forwardedFor, String realIp) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRemoteAddr(remoteAddr);
		if (forwardedFor != null) {
			request.addHeader("X-Forwarded-For", forwardedFor);
		}
		if (realIp != null) {
			request.addHeader("X-Real-IP", realIp);
		}
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
	}

	@Test
	@DisplayName("直连：同一客户端地址第二次请求被限流")
	void directConnectionIsLimitedByRemoteAddress() {
		DcrRateLimiter limiter = limiter(1);
		requestFrom("203.0.113.10", null, null);
		assertThatCode(limiter::check).doesNotThrowAnyException();
		assertThatThrownBy(limiter::check).isInstanceOf(DcrRejectedException.class);
	}

	@Test
	@DisplayName("直连：客户端伪造 X-Forwarded-For 无法绕过限流")
	void forgedForwardedHeaderIsIgnoredOnDirectConnection() {
		DcrRateLimiter limiter = limiter(1);
		requestFrom("203.0.113.10", "198.51.100.1", null);
		assertThatCode(limiter::check).doesNotThrowAnyException();
		// 换一个伪造值，仍应算作同一个客户端
		requestFrom("203.0.113.10", "198.51.100.2", null);
		assertThatThrownBy(limiter::check).isInstanceOf(DcrRejectedException.class);
	}

	@Test
	@DisplayName("代理后：不同真实客户端各自独立配额")
	void distinctClientsBehindProxyAreIndependent() {
		DcrRateLimiter limiter = limiter(1);
		requestFrom("10.0.0.5", "203.0.113.20", null);
		assertThatCode(limiter::check).doesNotThrowAnyException();
		requestFrom("10.0.0.5", "203.0.113.21", null);
		assertThatCode(limiter::check).doesNotThrowAnyException();
	}

	@Test
	@DisplayName("代理后：客户端伪造的最左段不影响真实客户端识别")
	void spoofedLeftmostSegmentDoesNotChangeClientKey() {
		DcrRateLimiter limiter = limiter(1);
		// 客户端自填 1.2.3.4，代理追加真实地址 203.0.113.30
		requestFrom("10.0.0.5", "1.2.3.4, 203.0.113.30", null);
		assertThatCode(limiter::check).doesNotThrowAnyException();
		requestFrom("10.0.0.5", "9.9.9.9, 203.0.113.30", null);
		assertThatThrownBy(limiter::check).isInstanceOf(DcrRejectedException.class);
	}

	@Test
	@DisplayName("代理后：无 X-Forwarded-For 时回退到 X-Real-IP")
	void fallsBackToRealIpHeader() {
		DcrRateLimiter limiter = limiter(1);
		requestFrom("10.0.0.5", null, "203.0.113.40");
		assertThatCode(limiter::check).doesNotThrowAnyException();
		requestFrom("10.0.0.5", null, "203.0.113.40");
		assertThatThrownBy(limiter::check).isInstanceOf(DcrRejectedException.class);
	}

	@Test
	@DisplayName("下一个时间窗口重新放行")
	void resetsOnNextWindow() {
		DcrRateLimiter limiter = limiter(1);
		requestFrom("203.0.113.10", null, null);
		assertThatCode(limiter::check).doesNotThrowAnyException();
		assertThatThrownBy(limiter::check).isInstanceOf(DcrRejectedException.class);
		this.now.addAndGet(61_000L);
		assertThatCode(limiter::check).doesNotThrowAnyException();
	}

	@Test
	@DisplayName("limit 为 0 时不限流")
	void zeroLimitDisablesProtection() {
		DcrRateLimiter limiter = limiter(0);
		requestFrom("203.0.113.10", null, null);
		for (int i = 0; i < 50; i++) {
			assertThatCode(limiter::check).doesNotThrowAnyException();
		}
	}

}
