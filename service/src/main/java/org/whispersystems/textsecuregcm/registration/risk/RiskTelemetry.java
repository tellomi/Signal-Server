/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.metrics.UserAgentTagUtil;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.ConditionResult;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.Reason;
import org.whispersystems.textsecuregcm.registration.risk.RiskRules.UserAgentClass;
import org.whispersystems.textsecuregcm.registration.risk.SourceNetworkClassifier.SourceNetwork;
import org.whispersystems.textsecuregcm.util.Util;

/// 评估器的全部输出：指标 + 结构化日志。**这里的任何一行都不带号码、IP、会话号、User-Agent 原文**（§6.2 隐私），
/// 只有聚合数字、平台、分类和判定结果。
///
/// 指标（前缀 `chat.RegistrationRiskAssessor.`）：
/// - `assessment{stage,outcome,failed,platform,push}`：每次评估一条。`outcome=wouldAllow` 就是「本来会放行」的数量（P2 判据）；
///   `failed` 是没通过的条号，如 `none` / `1` / `1+3`（① 已收过码 ② 机房 ③ 有异常 ④ 预算 / 转化率）
/// - `conditionFailed{stage,condition,reason}`：每条条件、每个具体原因没通过的次数（P2 判据）
/// - `sourceNetwork{class}`：来源网络分类（机房 / 名单外 / 判不出）
/// - `signal{signal}`：几个计数信号的分布（p50 / p90 / p99），用来定阈值
/// - `codeSent{cohort}`、`codeChecked{cohort,success}`：两组会话的发码 / 验码，转化率 = 验对 / 发码
/// - `error{stage,kind}`：`unavailable`（Redis 不可用 / 超时）、`internal`（代码错误）、`dropped`（后台队列满了）、
///   `rateLimited`（超过每秒记录数上限，攻击流量的量级也看这个）
/// - `datacenterNetworks`：配置的机房网段条数；0 = ② 这一条恒成立
final class RiskTelemetry {

  private static final Logger logger = LoggerFactory.getLogger(RegistrationRiskAssessor.class);

  private static final String ASSESSMENT = name(RegistrationRiskAssessor.class, "assessment");
  private static final String CONDITION_FAILED = name(RegistrationRiskAssessor.class, "conditionFailed");
  private static final String SOURCE_NETWORK = name(RegistrationRiskAssessor.class, "sourceNetwork");
  private static final String SIGNAL = name(RegistrationRiskAssessor.class, "signal");
  private static final String CODE_SENT = name(RegistrationRiskAssessor.class, "codeSent");
  private static final String CODE_CHECKED = name(RegistrationRiskAssessor.class, "codeChecked");
  private static final String ERROR = name(RegistrationRiskAssessor.class, "error");
  private static final String DATACENTER_NETWORKS = name(RegistrationRiskAssessor.class, "datacenterNetworks");

  /// 同一类告警日志最多每分钟一条（攻击或 Redis 故障时不刷屏），次数在 `error` 指标里
  private static final long WARNING_INTERVAL_MILLIS = 60_000;

  enum Stage {
    /// 建会话
    SESSION("session"),
    /// 发码前
    PRE_SEND("preSend"),
    /// 验证码发出去之后
    CODE_SENT("codeSent"),
    /// 验证码提交之后
    CODE_CHECKED("codeChecked");

    private final String tag;

    Stage(final String tag) {
      this.tag = tag;
    }

    String tag() {
      return tag;
    }
  }

  /// 一次评估的全部中间结果
  record Evaluation(RiskSnapshot snapshot, SourceNetwork sourceNetwork, UserAgentClass userAgentClass,
                    RiskAssessment assessment) {
  }

  private final MeterRegistry registry;
  private final Clock clock;
  private final AtomicLong lastUnavailableLogMillis = new AtomicLong(Long.MIN_VALUE);
  private final AtomicLong lastInternalLogMillis = new AtomicLong(Long.MIN_VALUE);
  private final AtomicLong lastDroppedLogMillis = new AtomicLong(Long.MIN_VALUE);
  private final AtomicLong lastRateLimitedLogMillis = new AtomicLong(Long.MIN_VALUE);

  RiskTelemetry(final MeterRegistry registry, final Clock clock, final SourceNetworkClassifier classifier) {
    this.registry = registry;
    this.clock = clock;

    Gauge.builder(DATACENTER_NETWORKS, classifier, SourceNetworkClassifier::networkCount).register(registry);
  }

  void assessment(final Stage stage, final RiskSignals signals, final Evaluation evaluation) {
    final RiskAssessment assessment = evaluation.assessment();
    final boolean wouldAllow = assessment.wouldAllow();
    final RiskSnapshot snapshot = evaluation.snapshot();

    registry.counter(ASSESSMENT, Tags.of(
            "stage", stage.tag(),
            "outcome", wouldAllow ? "wouldAllow" : "wouldChallenge",
            "failed", assessment.failedSignature(),
            "platform", UserAgentTagUtil.getPlatformTag(signals.userAgent()).getValue(),
            // 只有建会话请求带得出推送 token；发码前这一步不知道，不要给一个假的 false
            "push", stage == Stage.SESSION ? Boolean.toString(signals.pushTokenPresent()) : "n/a"))
        .increment();

    for (final ConditionResult failed : assessment.failedConditions()) {
      for (final Reason reason : failed.sortedFailedReasons()) {
        registry.counter(CONDITION_FAILED, Tags.of(
                "stage", stage.tag(),
                "condition", failed.condition().tag(),
                "reason", reason.tag()))
            .increment();
      }
    }

    if (stage == Stage.SESSION) {
      registry.counter(SOURCE_NETWORK, "class", evaluation.sourceNetwork().tag()).increment();

      signal("subnetSessions24h", snapshot.subnetSessions24h());
      signal("ipSessions24h", snapshot.ipSessions24h());
      signal("numberSessions24h", snapshot.numberSessions24h());
      signal("prefixCodes1h", snapshot.prefixSent1h());
    }

    final String message = "registration risk (record only): stage={} outcome={} failed={} platform={} push={} "
        + "countryCode={} network={} userAgent={} subnetSessions24h={} ipSessions24h={} numberSessions24h={} "
        + "numberCodes24h={} prefixCodes1h={} prefixVerified1h={} wouldAllowThisHour={} cohortCodes1h={} cohortVerified1h={}";
    final Object[] arguments = {
        stage.tag(),
        wouldAllow ? "wouldAllow" : "wouldChallenge",
        assessment.failedSignature(),
        UserAgentTagUtil.getPlatformTag(signals.userAgent()).getValue(),
        stage == Stage.SESSION ? signals.pushTokenPresent() : "n/a",
        Util.getCountryCode(signals.e164()),
        evaluation.sourceNetwork().tag(),
        evaluation.userAgentClass().tag(),
        snapshot.subnetSessions24h(),
        snapshot.ipSessions24h(),
        snapshot.numberSessions24h(),
        snapshot.numberCodes24h(),
        snapshot.prefixSent1h(),
        snapshot.prefixVerified1h(),
        snapshot.wouldAllowThisHour(),
        snapshot.cohortSent1h(),
        snapshot.cohortVerified1h()};

    // 「本来会放行」的数量有预算封顶，可以放心记 INFO；被拒的量没有上限（攻击时会很大），只记 DEBUG，看指标
    if (wouldAllow) {
      logger.info(message, arguments);
    } else {
      logger.debug(message, arguments);
    }
  }

  void codeSent(final Optional<RiskCohort> cohort) {
    registry.counter(CODE_SENT, "cohort", RiskCohort.tagOf(cohort)).increment();
  }

  void codeChecked(final Optional<RiskCohort> cohort, final boolean success) {
    registry.counter(CODE_CHECKED, "cohort", RiskCohort.tagOf(cohort), "success", Boolean.toString(success))
        .increment();
  }

  void failure(final Stage stage, final RuntimeException e) {
    final boolean unavailable = e instanceof RiskUnavailableException;

    registry.counter(ERROR, "stage", stage.tag(), "kind", unavailable ? "unavailable" : "internal").increment();

    if (unavailable) {
      if (shouldLog(lastUnavailableLogMillis)) {
        logger.warn("registration risk counters unavailable (stage={}); this record is skipped, registration is not affected",
            stage.tag(), e);
      }
    } else if (shouldLog(lastInternalLogMillis)) {
      logger.error("registration risk assessment failed (stage={}); ignored, registration is not affected",
          stage.tag(), e);
    }
  }

  void dropped(final Stage stage) {
    registry.counter(ERROR, "stage", stage.tag(), "kind", "dropped").increment();

    if (shouldLog(lastDroppedLogMillis)) {
      logger.warn("registration risk queue is full (stage={}); this record is dropped, registration is not affected",
          stage.tag());
    }
  }

  void rateLimited(final Stage stage) {
    registry.counter(ERROR, "stage", stage.tag(), "kind", "rateLimited").increment();

    if (shouldLog(lastRateLimitedLogMillis)) {
      logger.warn("registration risk records are above the per-second limit (stage={}); the excess is dropped, "
          + "registration is not affected", stage.tag());
    }
  }

  private void signal(final String signal, final long value) {
    DistributionSummary.builder(SIGNAL)
        .tag("signal", signal)
        .publishPercentiles(0.5, 0.9, 0.99)
        .register(registry)
        .record(value);
  }

  private boolean shouldLog(final AtomicLong lastLogMillis) {
    final long now = clock.millis();
    final long last = lastLogMillis.get();
    return (last == Long.MIN_VALUE || now - last >= WARNING_INTERVAL_MILLIS) && lastLogMillis.compareAndSet(last, now);
  }
}
