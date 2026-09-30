/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

/// 计数存储（Redis）不可用或超时，评估算不出来。
///
/// 调用方一律 fail-open：P2 里评估器把它吞掉、只记指标，建会话照常；P3 里「算不出来」等于「不放行」，也就是回到今天的行为（照旧出验证）。
public class RiskUnavailableException extends RuntimeException {

  public RiskUnavailableException(final Throwable cause) {
    super("registration risk counters are unavailable", cause);
  }
}
