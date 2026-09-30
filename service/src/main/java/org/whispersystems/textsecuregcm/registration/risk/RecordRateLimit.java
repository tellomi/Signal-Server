/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import java.time.Clock;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

/// 每秒最多记录多少个事件（按整秒的固定窗口数）。评估器往限流用的 Redis 里写键，攻击流量下键数和攻击速率成正比；
/// 这一道上限让最坏情况的键数有界（每秒 N 个事件 × 24 小时），超出的事件直接丢弃并记指标（同时也是攻击量的可见指标）。
///
/// 不阻塞，线程安全；窗口切换那一刻的极小误差不影响用途。
final class RecordRateLimit {

  private final Clock clock;
  private final int permitsPerSecond;
  private final AtomicLong currentSecond = new AtomicLong(Long.MIN_VALUE);
  private final AtomicInteger used = new AtomicInteger();

  RecordRateLimit(final Clock clock, final int permitsPerSecond) {
    this.clock = clock;
    this.permitsPerSecond = permitsPerSecond;
  }

  boolean tryAcquire() {
    final long second = clock.millis() / 1000;
    final long observed = currentSecond.get();

    if (second != observed && currentSecond.compareAndSet(observed, second)) {
      used.set(0);
    }
    return used.incrementAndGet() <= permitsPerSecond;
  }
}
