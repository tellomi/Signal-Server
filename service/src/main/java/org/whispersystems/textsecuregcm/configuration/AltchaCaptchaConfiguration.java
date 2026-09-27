/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import jakarta.annotation.Nullable;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import java.time.Duration;
import java.util.List;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/// Tellomi（ADR-0070 §5.3–5.4）：自托管工作量证明 ALTCHA，给大陆的注册验证页用（海外仍是 Turnstile）。
///
/// 令牌：`altcha.<keyId>.<action>.<base64url(控件提交内容)>`。
///
/// @param keyId                 现役 HMAC 密钥的编号（令牌第二段）；只允许小写字母和数字，因为 `CaptchaChecker` 会把这一段转成小写
/// @param secret                现役主密钥；签挑战、签派生结果、给网段计数的键加密钥，都由它派生
/// @param previousKeyId         轮换时的旧密钥编号：只用于校验（旧挑战最多再活一个有效期），不再签发；可以为空
/// @param previousSecret        旧主密钥，和 previousKeyId 一起给或一起不给
/// @param challengeTtl          挑战有效期，默认 10 分钟（§5.3）
/// @param tiers                 难度档，从低到高（§5.4 的 T0 / T1 / T2）；缺省用 ADR 里按 iPhone 实测定的三档
/// @param segmentThresholds     同一网段（IPv4 /24、IPv6 /56）最近一小时签发了多少个挑战之后升到下一档；长度 = 档数 − 1，严格递增
/// @param globalHourlyBudget    全局每小时签发预算：超过就给所有来源整体加一档并告警。**不拒收**（§2.1）
public record AltchaCaptchaConfiguration(@NotBlank @Pattern(regexp = KEY_ID_PATTERN) String keyId,
                                         @NotNull SecretString secret,
                                         @Nullable @Pattern(regexp = KEY_ID_PATTERN) String previousKeyId,
                                         @Nullable SecretString previousSecret,
                                         @Nullable Duration challengeTtl,
                                         @Nullable @Valid List<Tier> tiers,
                                         @Nullable List<Integer> segmentThresholds,
                                         @Nullable Integer globalHourlyBudget) {

  public static final String KEY_ID_PATTERN = "[a-z0-9]{1,16}";

  /// 一档难度：每次派生的迭代数 `cost`，服务端在 [minCounter, maxCounter] 里随机定目标计数，客户端要从 0 试到那里
  public record Tier(int cost, int minCounter, int maxCounter) {

    public Tier {
      if (cost < 1 || minCounter < 1 || maxCounter < minCounter) {
        throw new IllegalArgumentException("altcha tier needs cost ≥ 1 and 1 ≤ minCounter ≤ maxCounter: " + this);
      }
    }
  }

  /// ADR-0070 §5.4 表：T0 来源正常（iPhone 平均 0.46 秒），T1 偏热 / 全局异常（约 2 秒），T2 很热（约 6 秒，低端安卓估算 17–23 秒）
  public static final List<Tier> DEFAULT_TIERS = List.of(
      new Tier(1_000, 5_000, 10_000),
      new Tier(5_000, 5_000, 10_000),
      new Tier(5_000, 15_000, 30_000));

  public static final List<Integer> DEFAULT_SEGMENT_THRESHOLDS = List.of(30, 100);
  public static final int DEFAULT_GLOBAL_HOURLY_BUDGET = 3_000;
  public static final Duration DEFAULT_CHALLENGE_TTL = Duration.ofMinutes(10);

  public AltchaCaptchaConfiguration {
    if (challengeTtl == null) {
      challengeTtl = DEFAULT_CHALLENGE_TTL;
    }
    if (challengeTtl.isNegative() || challengeTtl.isZero() || challengeTtl.compareTo(Duration.ofHours(1)) > 0) {
      throw new IllegalArgumentException("altchaCaptcha.challengeTtl must be in (0, 1h]");
    }
    tiers = tiers == null || tiers.isEmpty() ? DEFAULT_TIERS : List.copyOf(tiers);
    segmentThresholds = segmentThresholds == null ? DEFAULT_SEGMENT_THRESHOLDS : List.copyOf(segmentThresholds);
    if (segmentThresholds.size() != tiers.size() - 1) {
      throw new IllegalArgumentException("altchaCaptcha.segmentThresholds needs exactly tiers.size() - 1 entries");
    }
    for (int i = 0; i < segmentThresholds.size(); i++) {
      if (segmentThresholds.get(i) < 1 || (i > 0 && segmentThresholds.get(i) <= segmentThresholds.get(i - 1))) {
        throw new IllegalArgumentException("altchaCaptcha.segmentThresholds must be positive and strictly increasing");
      }
    }
    if (globalHourlyBudget == null) {
      globalHourlyBudget = DEFAULT_GLOBAL_HOURLY_BUDGET;
    }
    if (globalHourlyBudget < 1) {
      throw new IllegalArgumentException("altchaCaptcha.globalHourlyBudget must be positive");
    }
    if ((previousKeyId == null) != (previousSecret == null)) {
      throw new IllegalArgumentException("altchaCaptcha.previousKeyId and previousSecret go together");
    }
    if (keyId != null && keyId.equals(previousKeyId)) {
      throw new IllegalArgumentException("altchaCaptcha.previousKeyId must differ from keyId");
    }
  }
}
