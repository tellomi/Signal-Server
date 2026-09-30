/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.util.TestClock;

/// 每秒记录数的上限：攻击流量下让 Redis 里的键数有界
class RecordRateLimitTest {

  @Test
  void allowsTheConfiguredNumberPerSecondAndRefusesTheRest() {
    final TestClock clock = TestClock.pinned(Instant.ofEpochSecond(1_000_000));
    final RecordRateLimit limit = new RecordRateLimit(clock, 3);

    assertThat(limit.tryAcquire()).isTrue();
    assertThat(limit.tryAcquire()).isTrue();
    assertThat(limit.tryAcquire()).isTrue();
    assertThat(limit.tryAcquire()).isFalse();
    assertThat(limit.tryAcquire()).isFalse();
  }

  @Test
  void theNextSecondStartsOver() {
    final TestClock clock = TestClock.pinned(Instant.ofEpochSecond(1_000_000));
    final RecordRateLimit limit = new RecordRateLimit(clock, 2);

    assertThat(limit.tryAcquire()).isTrue();
    assertThat(limit.tryAcquire()).isTrue();
    assertThat(limit.tryAcquire()).isFalse();

    clock.pin(Instant.ofEpochMilli(1_000_000_999));
    assertThat(limit.tryAcquire()).as("still the same second").isFalse();

    clock.pin(Instant.ofEpochSecond(1_000_001));
    assertThat(limit.tryAcquire()).isTrue();
    assertThat(limit.tryAcquire()).isTrue();
    assertThat(limit.tryAcquire()).isFalse();
  }

  @Test
  void neverExceedsTheLimitUnderConcurrency() throws Exception {
    final TestClock clock = TestClock.pinned(Instant.ofEpochSecond(1_000_000));
    final RecordRateLimit limit = new RecordRateLimit(clock, 50);
    final AtomicInteger granted = new AtomicInteger();
    final ExecutorService executor = Executors.newFixedThreadPool(16);

    try {
      final List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < 16; i++) {
        futures.add(executor.submit(() -> {
          for (int j = 0; j < 100; j++) {
            if (limit.tryAcquire()) {
              granted.incrementAndGet();
            }
          }
        }));
      }
      for (final Future<?> future : futures) {
        future.get(30, TimeUnit.SECONDS);
      }
    } finally {
      executor.shutdownNow();
    }

    // 1600 次尝试、上限 50：窗口内只放行 50 个（窗口切换那一刻的竞争在同一秒内不会发生）
    assertThat(granted.get()).isEqualTo(50);
  }
}
