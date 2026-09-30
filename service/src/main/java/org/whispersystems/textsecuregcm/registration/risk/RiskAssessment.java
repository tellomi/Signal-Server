/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import java.util.Comparator;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/// 一次评估的结果：**本来会不会放行**，以及 ADR-0070 §6.1 每一条放行条件各自的判定（含没通过的原因）。
///
/// 第 5 条（设备证明）这一期没有，不在结果里，对判定没有影响。
///
/// @param conditions 各条放行条件的结果，按条件编号从小到大；建会话时是 ①–④，发码前只有 ①–③（预算是建会话时才有的概念）
public record RiskAssessment(List<ConditionResult> conditions) {

  public RiskAssessment {
    conditions = List.copyOf(conditions);
  }

  /// §6.1 的放行条件。`tag` 是指标标签，`number` 是 ADR 里的条号
  public enum Condition {
    /// ① 这个号码 24 小时内还没收过我们的验证码（只放行每个号码每天的第一条）
    FIRST_CODE(1, "first-code"),
    /// ② 来源不是机房 / 云厂商网段
    NOT_DATACENTER(2, "not-datacenter"),
    /// ③ 来源网段、号段当前没有异常（§6.2）；User-Agent、同号会话数也算在这一条里
    NO_ANOMALY(3, "no-anomaly"),
    /// ④ 全局放行预算有余，而且「本来会放行」那一组会话的转化率健康（§6.3）
    BUDGET_HEALTHY(4, "budget-healthy");

    private final int number;
    private final String tag;

    Condition(final int number, final String tag) {
      this.number = number;
      this.tag = tag;
    }

    public int number() {
      return number;
    }

    public String tag() {
      return tag;
    }
  }

  /// 条件没通过的具体原因（指标标签）
  public enum Reason {
    CODE_ALREADY_SENT("code-already-sent"),
    DATACENTER("datacenter"),
    UNKNOWN_SOURCE("unknown-source"),
    SUBNET_SESSIONS("subnet-sessions"),
    IP_SESSIONS("ip-sessions"),
    NUMBER_SESSIONS("number-sessions"),
    PREFIX_VOLUME("prefix-volume"),
    PREFIX_CONVERSION("prefix-conversion"),
    USER_AGENT_UNRECOGNIZED("ua-unrecognized"),
    USER_AGENT_UNPUBLISHED("ua-unpublished"),
    GLOBAL_BUDGET("global-budget"),
    COHORT_CONVERSION("cohort-conversion");

    private final String tag;

    Reason(final String tag) {
      this.tag = tag;
    }

    public String tag() {
      return tag;
    }
  }

  /// 一条条件的判定；`failedReasons` 为空 = 通过
  public record ConditionResult(Condition condition, Set<Reason> failedReasons) {

    public ConditionResult {
      failedReasons = failedReasons.isEmpty() ? Set.of() : EnumSet.copyOf(failedReasons);
    }

    public boolean passed() {
      return failedReasons.isEmpty();
    }

    /// 没通过的原因，按枚举顺序（输出稳定）
    public List<Reason> sortedFailedReasons() {
      return failedReasons.stream().sorted(Comparator.naturalOrder()).toList();
    }
  }

  /// 所有条件都通过 = 本来会放行（P2 只记录，实际仍然出验证码）
  public boolean wouldAllow() {
    return conditions.stream().allMatch(ConditionResult::passed);
  }

  public Optional<ConditionResult> result(final Condition condition) {
    return conditions.stream().filter(result -> result.condition() == condition).findFirst();
  }

  public List<ConditionResult> failedConditions() {
    return conditions.stream().filter(result -> !result.passed()).toList();
  }

  /// 没通过的条号，例如 `"none"`、`"1"`、`"1+3"`。用作指标标签：最多 15 种组合，基数有限
  public String failedSignature() {
    final List<ConditionResult> failed = failedConditions();
    if (failed.isEmpty()) {
      return "none";
    }
    return failed.stream().map(result -> Integer.toString(result.condition().number())).collect(Collectors.joining("+"));
  }
}
