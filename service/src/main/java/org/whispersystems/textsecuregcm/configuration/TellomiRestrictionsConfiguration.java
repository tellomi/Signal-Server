/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;

/// Tellomi（ADR-0078 §3.3 第二刀，tellomi/tellomi#1368）：人工处置名单表 [org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions]。
///
/// 可选：不配这一段 = 没有处置（和上游一样）。名单由香港的 `deploy/hk/restrict.py` 改，服务端每 [#refreshInterval] 读一遍。
///
/// @param tableName       DynamoDB 表名
/// @param refreshInterval 多久重读一遍名单，默认 1 分钟（处置最晚这么久生效、解除最晚这么久放行）
/// @param numberHashKey   暂停时拦同号重新注册用的号码哈希密钥（≥ 32 字节，`secret://`）；不配就不拦号码
public record TellomiRestrictionsConfiguration(@NotBlank String tableName, @Nullable Duration refreshInterval,
                                               @Nullable SecretBytes numberHashKey) {

  public static final Duration DEFAULT_REFRESH_INTERVAL = Duration.ofMinutes(1);

  public TellomiRestrictionsConfiguration {
    if (numberHashKey != null && numberHashKey.value().length < 32) {
      throw new IllegalArgumentException("tellomiRestrictions.numberHashKey must be at least 32 bytes");
    }
  }

  public Duration refreshIntervalOrDefault() {
    return refreshInterval != null ? refreshInterval : DEFAULT_REFRESH_INTERVAL;
  }

  @Nullable
  public byte[] numberHashKeyBytes() {
    return numberHashKey != null ? numberHashKey.value() : null;
  }
}
