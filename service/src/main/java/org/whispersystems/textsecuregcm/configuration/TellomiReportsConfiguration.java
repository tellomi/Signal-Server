/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;

/// Tellomi（ADR-0078 §3.1，tellomi/tellomi#1368）：举报记录表 [org.whispersystems.textsecuregcm.storage.TellomiReports]。
///
/// 可选：不配这一段 = 和上游一样，举报只进 Redis 的计数、不留记录。
///
/// @param tableName DynamoDB 表名
/// @param retention 每条记录保留多久，到期由 DynamoDB TTL（香港是 `ddb-ttl-sweep`）删；默认 180 天（owner 2026-10-17 按推荐定）
public record TellomiReportsConfiguration(@NotBlank String tableName, @Nullable Duration retention) {

  public static final Duration DEFAULT_RETENTION = Duration.ofDays(180);

  public Duration retentionOrDefault() {
    return retention != null ? retention : DEFAULT_RETENTION;
  }
}
