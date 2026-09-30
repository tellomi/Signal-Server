/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import com.vdurmont.semver4j.Semver;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import java.time.Clock;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.configuration.RegistrationRiskConfiguration;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.registration.risk.RiskRules.UserAgentClass;
import org.whispersystems.textsecuregcm.registration.risk.RiskTelemetry.Evaluation;
import org.whispersystems.textsecuregcm.registration.risk.RiskTelemetry.Stage;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;

/// 注册风控评估器（ADR-0070 §6；tellomi/tellomi#1398 P2「只记录」）。
///
/// 给一次建会话算出：**本来会不会放行**，以及 §6.1 每一条放行条件（第 1–4 条；第 5 条设备证明这一期没有）各自的判定。
/// P2 里结果**只写指标和结构化日志**：调用方（`VerificationController`）照旧无条件要求验证码，用户可见的行为和没有这个类时逐字节一致。
///
/// **不影响主流程的保证**：
/// - `sessionCreated` / `codeRequested` / `codeSent` / `codeChecked` 只把事件放进一个有界队列就返回，评估和 Redis 读写都在后台线程；
///   队列满了就丢弃这一次记录（记 `error{kind=dropped}`），**永不阻塞请求线程**；
/// - 每秒记录数有上限（`maxRecordsPerSecond`），超出的丢弃（记 `error{kind=rateLimited}`）：攻击流量下 Redis 里的键数和速率成正比，
///   不设上限会挤占这套和限流共用的 Redis；
/// - 后台任务里的任何异常都吞掉，只记指标（`unavailable` = Redis 不可用 / 超时，`internal` = 代码错误），告警日志限频；
/// - 这四个方法本身不抛异常。
///
/// 整个评估器没配置（或 `enabled: false`）时用 [#disabled()]：每个方法都是空操作，请求路径上只多一次空方法调用。
///
/// 放行（P3）不在这一期：`assess` 是只读的，P3 要在建会话时同步拿结果，需要另加超时和「算不出来 = 不放行」的处理。
public class RegistrationRiskAssessor {

  private static final RegistrationRiskAssessor DISABLED = new RegistrationRiskAssessor();

  private final boolean enabled;
  @Nullable private final RegistrationRiskConfiguration configuration;
  @Nullable private final RegistrationRiskCounters counters;
  @Nullable private final Executor executor;
  @Nullable private final SourceNetworkClassifier sourceNetworkClassifier;
  @Nullable private final RiskTelemetry telemetry;
  @Nullable private final RecordRateLimit recordRateLimit;
  private final Map<ClientPlatform, Set<Semver>> publishedVersions;

  /// 空操作的评估器：没有配置 `registrationRisk` 块（或 `enabled: false`）时用它，行为和没有这个功能时一样
  public static RegistrationRiskAssessor disabled() {
    return DISABLED;
  }

  /// @param executor 后台线程池，必须是**有界队列**的，且提交任务不能阻塞（满了应该抛 `RejectedExecutionException`）
  public static RegistrationRiskAssessor create(final RegistrationRiskConfiguration configuration,
      final FaultTolerantRedisClusterClient redisCluster,
      final Clock clock,
      final Executor executor) {

    return create(configuration, redisCluster, clock, executor, Metrics.globalRegistry,
        SourceNetworkClassifier.fromCidrBlocks(configuration.datacenterNetworks()));
  }

  /// 可以换指标注册表和「机房」判定实现（测试用；以后换数据源也走这里）
  public static RegistrationRiskAssessor create(final RegistrationRiskConfiguration configuration,
      final FaultTolerantRedisClusterClient redisCluster,
      final Clock clock,
      final Executor executor,
      final MeterRegistry meterRegistry,
      final SourceNetworkClassifier sourceNetworkClassifier) {

    return new RegistrationRiskAssessor(configuration,
        new RegistrationRiskCounters(redisCluster, configuration.secret().value(), clock),
        executor,
        sourceNetworkClassifier,
        new RiskTelemetry(meterRegistry, clock, sourceNetworkClassifier),
        new RecordRateLimit(clock, configuration.maxRecordsPerSecond()));
  }

  private RegistrationRiskAssessor() {
    this.enabled = false;
    this.configuration = null;
    this.counters = null;
    this.executor = null;
    this.sourceNetworkClassifier = null;
    this.telemetry = null;
    this.recordRateLimit = null;
    this.publishedVersions = Map.of();
  }

  private RegistrationRiskAssessor(final RegistrationRiskConfiguration configuration,
      final RegistrationRiskCounters counters,
      final Executor executor,
      final SourceNetworkClassifier sourceNetworkClassifier,
      final RiskTelemetry telemetry,
      final RecordRateLimit recordRateLimit) {

    this.enabled = true;
    this.configuration = configuration;
    this.counters = counters;
    this.executor = executor;
    this.sourceNetworkClassifier = sourceNetworkClassifier;
    this.telemetry = telemetry;
    this.recordRateLimit = recordRateLimit;

    final Map<ClientPlatform, Set<Semver>> versions = new EnumMap<>(ClientPlatform.class);
    configuration.publishedClientVersions().forEach((platform, platformVersions) -> {
      final Set<Semver> parsed = new HashSet<>();
      platformVersions.forEach(version -> parsed.add(new Semver(version)));
      versions.put(ClientPlatform.valueOf(platform.toUpperCase(Locale.ROOT)), Set.copyOf(parsed));
    });
    this.publishedVersions = Map.copyOf(versions);
  }

  public boolean isEnabled() {
    return enabled;
  }

  /// 建会话之后调用：把这次会话记进计数，评估「本来会不会放行」，写指标和日志，并记下这个会话属于哪一组（供发码 / 验码归组）。
  /// 不阻塞、不抛异常。
  public void sessionCreated(final RiskSignals signals) {
    submit(Stage.SESSION, () -> {
      final RegistrationRiskCounters.Entities entities = counters.entities(signals);

      // 先记再读：`*Sessions24h` 包含当前这个会话
      counters.recordSession(entities);

      final Evaluation evaluation = evaluate(signals, entities, true);
      final boolean wouldAllow = evaluation.assessment().wouldAllow();

      if (wouldAllow) {
        counters.recordWouldAllow();
      }
      counters.setCohort(entities, RiskCohort.of(wouldAllow));

      telemetry.assessment(Stage.SESSION, signals, evaluation);
    });
  }

  /// 发码之前调用（ADR-0070 §6.1 发码前那一步）：只评估 ①–③，记下「这时候如果要重新验证，会是因为什么」。
  /// P2 只记录；P3 才会据此把验证要回来。不阻塞、不抛异常。
  public void codeRequested(final RiskSignals signals) {
    submit(Stage.PRE_SEND, () -> {
      final Evaluation evaluation = evaluate(signals, counters.entities(signals), false);

      telemetry.assessment(Stage.PRE_SEND, signals, evaluation);
    });
  }

  /// 验证码发出去之后调用：号码的 24 小时发码数、号段的 1 小时发码数加 1，按会话的分组累计发码数。不阻塞、不抛异常。
  public void codeSent(final RiskSignals signals) {
    submit(Stage.CODE_SENT, () -> {
      final RegistrationRiskCounters.Entities entities = counters.entities(signals);

      counters.recordCodeSent(entities);

      final Optional<RiskCohort> cohort = counters.cohort(entities);
      if (cohort.filter(RiskCohort.WOULD_ALLOW::equals).isPresent()) {
        counters.recordCohortSent();
      }
      telemetry.codeSent(cohort);
    });
  }

  /// 验证码提交之后调用。验对了才累计号段的验证成功数和分组的验证成功数（转化率的分子）。不阻塞、不抛异常。
  public void codeChecked(final RiskSignals signals, final boolean verified) {
    submit(Stage.CODE_CHECKED, () -> {
      final RegistrationRiskCounters.Entities entities = counters.entities(signals);
      final Optional<RiskCohort> cohort = counters.cohort(entities);

      if (verified) {
        counters.recordVerified(entities);

        if (cohort.filter(RiskCohort.WOULD_ALLOW::equals).isPresent()) {
          counters.recordCohortVerified();
        }
      }
      telemetry.codeChecked(cohort, verified);
    });
  }

  /// 只读地评估一次建会话（判 ①–④）：读当前计数，不改任何计数。同步、可能抛异常，**不在请求路径上用**；
  /// 给测试和 P3 用。
  ///
  /// @throws RiskUnavailableException 计数存储不可用
  public RiskAssessment assess(final RiskSignals signals) {
    requireEnabled();
    return evaluate(signals, counters.entities(signals), true).assessment();
  }

  /// 只读地评估发码前那一步（判 ①–③）
  ///
  /// @throws RiskUnavailableException 计数存储不可用
  public RiskAssessment assessBeforeSend(final RiskSignals signals) {
    requireEnabled();
    return evaluate(signals, counters.entities(signals), false).assessment();
  }

  private Evaluation evaluate(final RiskSignals signals, final RegistrationRiskCounters.Entities entities,
      final boolean includeBudget) {

    final RiskSnapshot snapshot = counters.read(entities);
    final SourceNetworkClassifier.SourceNetwork sourceNetwork =
        sourceNetworkClassifier.classify(signals.sourceAddress());
    final UserAgentClass userAgentClass = RiskRules.classifyUserAgent(signals.userAgent(), publishedVersions);

    return new Evaluation(snapshot, sourceNetwork, userAgentClass,
        RiskRules.evaluate(snapshot, sourceNetwork, userAgentClass, configuration, includeBudget));
  }

  /// 把任务放进有界队列就返回；任务里的异常全部吞掉，只记指标
  private void submit(final Stage stage, final Runnable task) {
    if (!enabled) {
      return;
    }

    try {
      if (!recordRateLimit.tryAcquire()) {
        // 每秒记录数的上限：攻击流量下别把 Redis 写满（键数 = 速率 × 24 小时）
        telemetry.rateLimited(stage);
        return;
      }

      executor.execute(() -> {
        try {
          task.run();
        } catch (final RuntimeException e) {
          recordFailure(stage, e);
        }
      });
    } catch (final RejectedExecutionException e) {
      recordDropped(stage);
    } catch (final RuntimeException e) {
      recordFailure(stage, e);
    }
  }

  private void recordFailure(final Stage stage, final RuntimeException e) {
    try {
      telemetry.failure(stage, e);
    } catch (final RuntimeException ignored) {
      // 连记指标都失败了也不能影响任何人
    }
  }

  private void recordDropped(final Stage stage) {
    try {
      telemetry.dropped(stage);
    } catch (final RuntimeException ignored) {
    }
  }

  private void requireEnabled() {
    if (!enabled) {
      throw new IllegalStateException("registration risk assessor is disabled");
    }
  }
}
