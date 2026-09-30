/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import java.util.Optional;
import javax.annotation.Nullable;

/// 一个会话在建会话那一刻被评估成什么：「本来会放行」还是「本来会出验证」。
///
/// 发码 / 验码的事件靠它把结果归到对应的组里，得到两组会话各自的发码 → 验证成功转化率（§6.3 第 1 步要看的数据，
/// 也是 §6.1 第 4 条「放行会话的转化率健康」的口径）。P2 没有真正放行的会话，所以这一组是「假如放行了」的会话。
enum RiskCohort {

  WOULD_ALLOW("A", "wouldAllow"),
  WOULD_CHALLENGE("C", "wouldChallenge");

  /// 指标标签：会话的分组没记录（过期了，或者是开关打开之前建的会话）
  static final String UNKNOWN_TAG = "unknown";

  private final String flag;
  private final String tag;

  RiskCohort(final String flag, final String tag) {
    this.flag = flag;
    this.tag = tag;
  }

  String flag() {
    return flag;
  }

  String tag() {
    return tag;
  }

  static RiskCohort of(final boolean wouldAllow) {
    return wouldAllow ? WOULD_ALLOW : WOULD_CHALLENGE;
  }

  static Optional<RiskCohort> fromFlag(@Nullable final String flag) {
    for (final RiskCohort cohort : values()) {
      if (cohort.flag.equals(flag)) {
        return Optional.of(cohort);
      }
    }
    return Optional.empty();
  }

  static String tagOf(final Optional<RiskCohort> cohort) {
    return cohort.map(RiskCohort::tag).orElse(UNKNOWN_TAG);
  }
}
