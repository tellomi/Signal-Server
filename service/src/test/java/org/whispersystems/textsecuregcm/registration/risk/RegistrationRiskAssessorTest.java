/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executor;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.RegistrationRiskConfiguration;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.redis.RedisClusterExtension;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.Condition;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.Reason;
import org.whispersystems.textsecuregcm.util.TestClock;

/// ADR-0070 §6.1 第 1–4 条、§6.2 的信号、§6.3 第 1 步、§十 P2 判据：「本来会放行」和每条条件不满足的计数都看得见；
/// 任何依赖出问题都 fail-open，不拖慢、不搞坏调用方；键、指标、日志里没有号码 / IP / 会话号原文。
///
/// Redis 用真的（集群）；评估器的线程池换成同线程执行，这样每一步之后指标立刻可查。
class RegistrationRiskAssessorTest {

  @RegisterExtension
  static final RedisClusterExtension REDIS_CLUSTER_EXTENSION = RedisClusterExtension.builder().build();

  private static final String METER_PREFIX = "chat.RegistrationRiskAssessor.";
  private static final String ANDROID_UA = "Signal-Android/0.1.2 Android/34 Build/175101";
  private static final String HOME_IP = "203.0.113.10";

  private TestClock clock;
  private SimpleMeterRegistry meterRegistry;
  private ListAppender<ILoggingEvent> logAppender;
  private ch.qos.logback.classic.Logger riskLogger;
  private int sessionCounter;

  @BeforeEach
  void setUp() {
    clock = TestClock.pinned(Instant.ofEpochSecond(490_000L * 3600 + 1800));
    meterRegistry = new SimpleMeterRegistry();

    riskLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(RegistrationRiskAssessor.class);
    riskLogger.setLevel(Level.DEBUG);
    logAppender = new ListAppender<>();
    logAppender.start();
    riskLogger.addAppender(logAppender);
  }

  @AfterEach
  void tearDown() {
    riskLogger.detachAppender(logAppender);
    riskLogger.setLevel(null);
  }

  private RegistrationRiskAssessor assessor(final TestRiskConfig config) {
    final RegistrationRiskConfiguration configuration = config.build();

    return RegistrationRiskAssessor.create(configuration, REDIS_CLUSTER_EXTENSION.getRedisCluster(), clock,
        Runnable::run, meterRegistry, SourceNetworkClassifier.fromCidrBlocks(configuration.datacenterNetworks()));
  }

  private RegistrationRiskAssessor assessor() {
    return assessor(new TestRiskConfig());
  }

  private static String number(final int n) {
    return String.format("+861380013%04d", n);
  }

  private String newSessionId() {
    return "session-" + (++sessionCounter);
  }

  private static RiskSignals signals(final String ip, final String e164, final String userAgent, final String sessionId) {
    return new RiskSignals(ip, e164, userAgent, sessionId, false);
  }

  /// 建一个会话并返回它的信号（后面发码 / 验码要用同一个会话号）
  private RiskSignals createSession(final RegistrationRiskAssessor assessor, final String ip, final String e164) {
    final RiskSignals signals = signals(ip, e164, ANDROID_UA, newSessionId());
    assessor.sessionCreated(signals);
    return signals;
  }

  private void sendCode(final RegistrationRiskAssessor assessor, final RiskSignals session) {
    assessor.codeSent(RiskSignals.forSession(session.e164(), session.sessionId()));
  }

  private void verifyCode(final RegistrationRiskAssessor assessor, final RiskSignals session, final boolean verified) {
    assessor.codeChecked(RiskSignals.forSession(session.e164(), session.sessionId()), verified);
  }

  private double count(final String meter, final String... tags) {
    return meterRegistry.find(METER_PREFIX + meter).tags(tags).counters().stream().mapToDouble(Counter::count).sum();
  }

  private double sessionAssessments(final String outcome, final String failed) {
    return count("assessment", "stage", "session", "outcome", outcome, "failed", failed);
  }

  private List<ILoggingEvent> logEvents(final Level level) {
    return logAppender.list.stream().filter(event -> event.getLevel() == level).toList();
  }

  // ADR-0070 §6.1 ①–④ + P2 判据：本来会放行的数量、每条条件不满足的计数

  @Test
  void aQuietFirstSessionWouldBeAllowed() {
    final RegistrationRiskAssessor assessor = assessor();

    final RiskSignals session = createSession(assessor, HOME_IP, number(1));

    assertThat(count("assessment", "stage", "session", "outcome", "wouldAllow", "failed", "none", "platform", "android",
        "push", "false")).isEqualTo(1);
    assertThat(meterRegistry.find(METER_PREFIX + "conditionFailed").meters()).as("nothing failed").isEmpty();
    assertThat(count("sourceNetwork", "class", "unlisted")).isEqualTo(1);

    // 同一个会话再只读地问一次（含它自己）：还是本来会放行，且没有改任何计数
    assertThat(assessor.assess(session).wouldAllow()).isTrue();
  }

  @Test
  void condition1_aNumberThatAlreadyReceivedACodeIsNotAllowedAgain() {
    final RegistrationRiskAssessor assessor = assessor();

    final RiskSignals first = createSession(assessor, HOME_IP, number(1));
    sendCode(assessor, first);

    // 同一个号码换个网段再建会话：24 小时内已经收过码
    createSession(assessor, "198.51.100.5", number(1));

    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(1);
    assertThat(sessionAssessments("wouldChallenge", "1")).isEqualTo(1);
    assertThat(count("conditionFailed", "stage", "session", "condition", "first-code", "reason", "code-already-sent"))
        .isEqualTo(1);
  }

  @Test
  void condition1_theNumberIsFreshAgainAfterADay() {
    final RegistrationRiskAssessor assessor = assessor();

    sendCode(assessor, createSession(assessor, HOME_IP, number(1)));

    clock.pin(clock.instant().plus(Duration.ofHours(24)));
    createSession(assessor, "198.51.100.5", number(1));

    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(2);
  }

  @Test
  void condition2_aDatacenterSourceIsNeverAllowed() {
    final TestRiskConfig config = new TestRiskConfig();
    config.datacenterNetworks = List.of("203.0.113.0/24");
    final RegistrationRiskAssessor assessor = assessor(config);

    createSession(assessor, "203.0.113.77", number(1));
    createSession(assessor, "198.51.100.5", number(2));

    assertThat(sessionAssessments("wouldChallenge", "2")).isEqualTo(1);
    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(1);
    assertThat(count("conditionFailed", "condition", "not-datacenter", "reason", "datacenter")).isEqualTo(1);
    assertThat(count("sourceNetwork", "class", "datacenter")).isEqualTo(1);
    assertThat(count("sourceNetwork", "class", "unlisted")).isEqualTo(1);
    assertThat(meterRegistry.get(METER_PREFIX + "datacenterNetworks").gauge().value()).isEqualTo(1);
    assertThat(assessor.isEnabled()).isTrue();
  }

  @Test
  void condition2_anUnknownSourceIsNotAllowedEither() {
    final RegistrationRiskAssessor assessor = assessor();

    assessor.sessionCreated(new RiskSignals(null, number(1), ANDROID_UA, newSessionId(), false));

    assertThat(sessionAssessments("wouldChallenge", "2")).isEqualTo(1);
    assertThat(count("conditionFailed", "condition", "not-datacenter", "reason", "unknown-source")).isEqualTo(1);
    assertThat(count("sourceNetwork", "class", "unknown")).isEqualTo(1);
  }

  @Test
  void condition2_withoutAConfiguredListItHoldsForEveryoneAndTheGaugeSaysSo() {
    final RegistrationRiskAssessor assessor = assessor();

    createSession(assessor, "203.0.113.77", number(1));

    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(1);
    assertThat(meterRegistry.get(METER_PREFIX + "datacenterNetworks").gauge().value()).isZero();
    assertThat(assessor.isEnabled()).isTrue();
  }

  @Test
  void condition3_manySessionsFromOneSubnet() {
    final TestRiskConfig config = new TestRiskConfig();
    config.maxSubnetSessionsPerDay = 3;
    final RegistrationRiskAssessor assessor = assessor(config);

    for (int i = 1; i <= 4; i++) {
      createSession(assessor, "203.0.113." + i, number(i));
    }

    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(3);
    assertThat(sessionAssessments("wouldChallenge", "3")).isEqualTo(1);
    assertThat(count("conditionFailed", "condition", "no-anomaly", "reason", "subnet-sessions")).isEqualTo(1);

    // 别的网段不受影响：只让攻击来源变慢（§2.1 第 3 点）
    createSession(assessor, "198.51.100.1", number(5));
    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(4);
  }

  @Test
  void condition3_manySessionsFromOneIp() {
    final TestRiskConfig config = new TestRiskConfig();
    config.maxIpSessionsPerDay = 2;
    final RegistrationRiskAssessor assessor = assessor(config);

    for (int i = 1; i <= 3; i++) {
      createSession(assessor, HOME_IP, number(i));
    }

    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(2);
    assertThat(count("conditionFailed", "reason", "ip-sessions")).isEqualTo(1);
    assertThat(count("conditionFailed", "reason", "subnet-sessions")).isZero();
  }

  @Test
  void condition3_manySessionsForOneNumber() {
    final TestRiskConfig config = new TestRiskConfig();
    config.maxNumberSessionsPerDay = 2;
    final RegistrationRiskAssessor assessor = assessor(config);

    for (int i = 1; i <= 3; i++) {
      createSession(assessor, "198.51.100." + i, number(1));
    }

    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(2);
    assertThat(count("conditionFailed", "reason", "number-sessions")).isEqualTo(1);
  }

  @Test
  void condition3_aSegmentThatIsSendingTooManyCodes() {
    final TestRiskConfig config = new TestRiskConfig();
    config.maxPrefixCodesPerHour = 3;
    final RegistrationRiskAssessor assessor = assessor(config);

    for (int i = 1; i <= 4; i++) {
      sendCode(assessor, createSession(assessor, "198.51.100." + i, number(i)));
    }
    assertThat(count("conditionFailed", "reason", "prefix-volume")).as("codes go out after the assessment").isZero();

    // 号段最近一小时已经发了 4 条 > 3：同号段的新会话有异常
    createSession(assessor, "198.51.100.50", number(5));
    assertThat(count("conditionFailed", "condition", "no-anomaly", "reason", "prefix-volume")).isEqualTo(1);

    // 另一个号段（+86 139…）不受影响
    assessor.sessionCreated(signals("198.51.100.60", "+8613900139000", ANDROID_UA, newSessionId()));
    assertThat(count("conditionFailed", "reason", "prefix-volume")).isEqualTo(1);
  }

  @Test
  void condition3_aSegmentWhereCodesAreSentButNotVerified() {
    final TestRiskConfig config = new TestRiskConfig();
    config.minPrefixSamples = 4;
    config.minPrefixConversion = 0.5;
    final RegistrationRiskAssessor assessor = assessor(config);

    final List<RiskSignals> sessions = new ArrayList<>();
    for (int i = 1; i <= 4; i++) {
      final RiskSignals session = createSession(assessor, "198.51.100." + i, number(i));
      sendCode(assessor, session);
      sessions.add(session);
    }
    // 发了 4 条，只验对 1 条：25% < 50%
    verifyCode(assessor, sessions.get(0), true);
    verifyCode(assessor, sessions.get(1), false);

    createSession(assessor, "198.51.100.50", number(5));
    assertThat(count("conditionFailed", "condition", "no-anomaly", "reason", "prefix-conversion")).isEqualTo(1);

    // 再验对 1 条：50%，恢复
    verifyCode(assessor, sessions.get(2), true);
    createSession(assessor, "198.51.100.51", number(6));
    assertThat(count("conditionFailed", "reason", "prefix-conversion")).isEqualTo(1);
  }

  @Test
  void condition3_userAgentsThatAreNotOurPublishedClients() {
    final TestRiskConfig config = new TestRiskConfig();
    config.publishedClientVersions = Map.of("android", List.of("0.1.3"));
    final RegistrationRiskAssessor assessor = assessor(config);

    assessor.sessionCreated(signals("198.51.100.1", number(1), "curl/8.4.0", newSessionId()));
    assessor.sessionCreated(signals("198.51.100.2", number(2), null, newSessionId()));
    assessor.sessionCreated(signals("198.51.100.3", number(3), ANDROID_UA, newSessionId()));
    assessor.sessionCreated(signals("198.51.100.4", number(4), "Signal-Android/0.1.3 Android/34", newSessionId()));

    assertThat(count("conditionFailed", "reason", "ua-unrecognized")).isEqualTo(2);
    assertThat(count("conditionFailed", "reason", "ua-unpublished")).isEqualTo(1);
    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(1);
    assertThat(count("assessment", "stage", "session", "platform", "unrecognized")).isEqualTo(2);
    assertThat(count("assessment", "stage", "session", "platform", "android")).isEqualTo(2);
  }

  @Test
  void condition4_theHourlyBudgetCapsHowManyWouldBeAllowed() {
    final TestRiskConfig config = new TestRiskConfig();
    config.globalHourlyBudget = 2;
    final RegistrationRiskAssessor assessor = assessor(config);

    for (int i = 1; i <= 3; i++) {
      createSession(assessor, "198.51." + i + ".1", number(i));
    }

    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(2);
    assertThat(sessionAssessments("wouldChallenge", "4")).as("eligible on 1–3 but the budget is spent").isEqualTo(1);
    assertThat(count("conditionFailed", "condition", "budget-healthy", "reason", "global-budget")).isEqualTo(1);

    // 下一个整点小时：预算重新算
    clock.pin(clock.instant().plus(Duration.ofHours(1)));
    createSession(assessor, "198.51.9.1", number(9));
    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(3);
  }

  @Test
  void condition4_onlyWouldAllowSessionsSpendTheBudget() {
    final TestRiskConfig config = new TestRiskConfig();
    config.globalHourlyBudget = 1;
    config.datacenterNetworks = List.of("203.0.113.0/24");
    final RegistrationRiskAssessor assessor = assessor(config);

    // 机房来源本来就不放行，不占预算
    createSession(assessor, "203.0.113.5", number(1));
    createSession(assessor, "203.0.113.6", number(2));
    createSession(assessor, "198.51.100.1", number(3));

    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(1);
    assertThat(sessionAssessments("wouldChallenge", "2")).isEqualTo(2);
    assertThat(count("conditionFailed", "reason", "global-budget")).as("the budget was still free for #3").isZero();
  }

  @Test
  void condition4_theWouldAllowGroupMustConvert() {
    final TestRiskConfig config = new TestRiskConfig();
    config.minCohortSamples = 4;
    config.minCohortConversion = 0.5;
    config.datacenterNetworks = List.of("203.0.113.0/24");
    final RegistrationRiskAssessor assessor = assessor(config);

    // 4 个「本来会放行」的会话都发了码，只验对 1 个：25%
    final List<RiskSignals> allowed = new ArrayList<>();
    for (int i = 1; i <= 4; i++) {
      final RiskSignals session = createSession(assessor, "198.51." + i + ".1", number(i));
      sendCode(assessor, session);
      allowed.add(session);
    }
    verifyCode(assessor, allowed.get(0), true);

    // 「本来会出验证」的会话（机房来源）发了码没验，不算进这一组
    sendCode(assessor, createSession(assessor, "203.0.113.5", number(50)));

    createSession(assessor, "198.51.50.1", number(60));
    assertThat(sessionAssessments("wouldChallenge", "4")).as("eligible on 1–3, unhealthy on 4").isEqualTo(1);
    // 机房那个会话也判了第 4 条（四条独立判定，所以它是「2+4」）：这一组转化率不健康，两次都记
    assertThat(sessionAssessments("wouldChallenge", "2+4")).isEqualTo(1);
    assertThat(count("conditionFailed", "condition", "budget-healthy", "reason", "cohort-conversion")).isEqualTo(2);

    // 再验对 2 个：75%，恢复
    verifyCode(assessor, allowed.get(1), true);
    verifyCode(assessor, allowed.get(2), true);
    createSession(assessor, "198.51.51.1", number(61));
    assertThat(sessionAssessments("wouldAllow", "none")).isEqualTo(5);
  }

  @Test
  void everyConditionIsEvaluatedEvenWhenAnEarlierOneFails() {
    final TestRiskConfig config = new TestRiskConfig();
    config.datacenterNetworks = List.of("203.0.113.0/24");
    config.globalHourlyBudget = 1;
    final RegistrationRiskAssessor assessor = assessor(config);

    sendCode(assessor, createSession(assessor, "198.51.100.1", number(1)));

    // ① 号码已收过码 + ② 机房 + ③ curl 的 User-Agent；预算被上一个会话用掉了 → ④
    assessor.sessionCreated(signals("203.0.113.9", number(1), "curl/8", newSessionId()));

    assertThat(sessionAssessments("wouldChallenge", "1+2+3+4")).isEqualTo(1);
    assertThat(count("conditionFailed", "stage", "session", "condition", "first-code")).isEqualTo(1);
    assertThat(count("conditionFailed", "stage", "session", "condition", "not-datacenter")).isEqualTo(1);
    assertThat(count("conditionFailed", "stage", "session", "condition", "no-anomaly")).isEqualTo(1);
    assertThat(count("conditionFailed", "stage", "session", "condition", "budget-healthy")).isEqualTo(1);
  }

  @Test
  void pushTokenSessionsAreTaggedSoTheyCanBeSeenSeparately() {
    final RegistrationRiskAssessor assessor = assessor();

    assessor.sessionCreated(new RiskSignals(HOME_IP, number(1), ANDROID_UA, newSessionId(), true));
    assessor.sessionCreated(new RiskSignals("198.51.100.1", number(2), ANDROID_UA, newSessionId(), false));

    assertThat(count("assessment", "stage", "session", "push", "true")).isEqualTo(1);
    assertThat(count("assessment", "stage", "session", "push", "false")).isEqualTo(1);
  }

  // 发码前（§6.1 发码前那一步）：只评估 ①–③

  @Test
  void beforeSendOnlyLooksAtConditions1To3() {
    final TestRiskConfig config = new TestRiskConfig();
    config.globalHourlyBudget = 1;
    final RegistrationRiskAssessor assessor = assessor(config);

    final RiskSignals session = createSession(assessor, HOME_IP, number(1));
    createSession(assessor, "198.51.100.1", number(2));
    assertThat(sessionAssessments("wouldChallenge", "4")).as("budget of 1 is spent").isEqualTo(1);

    assessor.codeRequested(session);

    assertThat(count("assessment", "stage", "preSend", "outcome", "wouldAllow", "failed", "none", "push", "n/a"))
        .isEqualTo(1);
    assertThat(count("conditionFailed", "stage", "preSend")).isZero();
  }

  @Test
  void beforeSendNoticesThatACodeWentOutInTheMeantime() {
    final RegistrationRiskAssessor assessor = assessor();

    final RiskSignals session = createSession(assessor, HOME_IP, number(1));
    assessor.codeRequested(session);
    sendCode(assessor, session);
    // 客户端再请求一次（重发）：这个号码 24 小时内已经收过我们的码
    assessor.codeRequested(session);

    assertThat(count("assessment", "stage", "preSend", "outcome", "wouldAllow")).isEqualTo(1);
    assertThat(count("assessment", "stage", "preSend", "outcome", "wouldChallenge", "failed", "1")).isEqualTo(1);
    assertThat(count("conditionFailed", "stage", "preSend", "condition", "first-code", "reason", "code-already-sent"))
        .isEqualTo(1);
    // 发码前那一步不重复记「来源网络」和信号分布，只记判定
    assertThat(count("sourceNetwork")).isEqualTo(1);
  }

  // 发码 / 验码：按会话的分组累计（转化率）

  @Test
  void codesAndChecksAreCountedPerCohort() {
    final TestRiskConfig config = new TestRiskConfig();
    config.datacenterNetworks = List.of("203.0.113.0/24");
    final RegistrationRiskAssessor assessor = assessor(config);

    final RiskSignals allowed = createSession(assessor, "198.51.100.1", number(1));
    final RiskSignals challenged = createSession(assessor, "203.0.113.5", number(2));
    final RiskSignals unknownSession = signals(HOME_IP, number(3), ANDROID_UA, "session-the-assessor-never-saw");

    sendCode(assessor, allowed);
    sendCode(assessor, challenged);
    sendCode(assessor, unknownSession);
    verifyCode(assessor, allowed, true);
    verifyCode(assessor, challenged, false);
    verifyCode(assessor, unknownSession, true);

    assertThat(count("codeSent", "cohort", "wouldAllow")).isEqualTo(1);
    assertThat(count("codeSent", "cohort", "wouldChallenge")).isEqualTo(1);
    assertThat(count("codeSent", "cohort", "unknown")).isEqualTo(1);
    assertThat(count("codeChecked", "cohort", "wouldAllow", "success", "true")).isEqualTo(1);
    assertThat(count("codeChecked", "cohort", "wouldChallenge", "success", "false")).isEqualTo(1);
    assertThat(count("codeChecked", "cohort", "unknown", "success", "true")).isEqualTo(1);
  }

  // 每个会话的信号分布（用来定阈值）

  @Test
  void signalDistributionsAreRecordedForTuningThresholds() {
    final RegistrationRiskAssessor assessor = assessor();

    for (int i = 1; i <= 3; i++) {
      createSession(assessor, HOME_IP, number(1));
    }

    final DistributionSummary summary =
        meterRegistry.get(METER_PREFIX + "signal").tag("signal", "numberSessions24h").summary();
    assertThat(summary.count()).isEqualTo(3);
    assertThat(summary.max()).isEqualTo(3);
    assertThat(meterRegistry.find(METER_PREFIX + "signal").meters()).extracting(meter -> meter.getId().getTag("signal"))
        .containsExactlyInAnyOrder("subnetSessions24h", "ipSessions24h", "numberSessions24h", "prefixCodes1h");
  }

  // 只读的评估

  @Test
  void assessNeverChangesAnyCounter() {
    final RegistrationRiskAssessor assessor = assessor();
    final RiskSignals session = createSession(assessor, HOME_IP, number(1));
    sendCode(assessor, session);

    final Map<String, String> before = redisContents();

    final RiskAssessment first = assessor.assess(session);
    final RiskAssessment second = assessor.assess(session);
    final RiskAssessment beforeSend = assessor.assessBeforeSend(session);

    assertThat(redisContents()).isEqualTo(before);
    assertThat(second).isEqualTo(first);
    assertThat(first.failedSignature()).isEqualTo("1");
    assertThat(first.conditions()).extracting(RiskAssessment.ConditionResult::condition)
        .containsExactly(Condition.FIRST_CODE, Condition.NOT_DATACENTER, Condition.NO_ANOMALY, Condition.BUDGET_HEALTHY);
    assertThat(beforeSend.conditions()).hasSize(3);
    assertThat(first.result(Condition.FIRST_CODE).orElseThrow().failedReasons()).containsExactly(Reason.CODE_ALREADY_SENT);
  }

  // 关掉

  @Test
  void aDisabledAssessorDoesNothing() {
    final RegistrationRiskAssessor disabled = RegistrationRiskAssessor.disabled();
    final RiskSignals signals = signals(HOME_IP, number(1), ANDROID_UA, "s");

    assertThat(disabled.isEnabled()).isFalse();
    assertThatCode(() -> {
      disabled.sessionCreated(signals);
      disabled.codeRequested(signals);
      disabled.codeSent(signals);
      disabled.codeChecked(signals, true);
    }).doesNotThrowAnyException();
    assertThatThrownBy(() -> disabled.assess(signals)).isInstanceOf(IllegalStateException.class);
    assertThatThrownBy(() -> disabled.assessBeforeSend(signals)).isInstanceOf(IllegalStateException.class);

    assertThat(redisContents()).isEmpty();
    assertThat(meterRegistry.getMeters()).isEmpty();
  }

  // fail-open：依赖出问题、队列满了、代码出错，都只记指标

  @Test
  void whenRedisIsDownTheCallersAreNotAffectedAndOnlyMetricsAndOneWarningAreLeft() {
    final FaultTolerantRedisClusterClient brokenCluster = mock(FaultTolerantRedisClusterClient.class);
    when(brokenCluster.withCluster(any())).thenThrow(new RuntimeException("connection refused"));

    final RegistrationRiskAssessor assessor = RegistrationRiskAssessor.create(new TestRiskConfig().build(), brokenCluster,
        clock, Runnable::run, meterRegistry, SourceNetworkClassifier.fromCidrBlocks(List.of()));
    final RiskSignals signals = signals(HOME_IP, number(1), ANDROID_UA, "s");

    assertThatCode(() -> {
      assessor.sessionCreated(signals);
      assessor.codeRequested(signals);
      assessor.codeSent(signals);
      assessor.codeChecked(signals, true);
      assessor.sessionCreated(signals);
    }).doesNotThrowAnyException();

    assertThat(count("error", "stage", "session", "kind", "unavailable")).isEqualTo(2);
    assertThat(count("error", "stage", "preSend", "kind", "unavailable")).isEqualTo(1);
    assertThat(count("error", "stage", "codeSent", "kind", "unavailable")).isEqualTo(1);
    assertThat(count("error", "stage", "codeChecked", "kind", "unavailable")).isEqualTo(1);
    assertThat(count("assessment")).as("nothing is reported as assessed").isZero();

    // 告警日志限频：Redis 挂着的时候不会一次请求一条
    assertThat(logEvents(Level.WARN)).hasSize(1);
    clock.pin(clock.instant().plus(Duration.ofSeconds(61)));
    assessor.sessionCreated(signals);
    assertThat(logEvents(Level.WARN)).hasSize(2);
    assertThat(count("error", "kind", "unavailable")).isEqualTo(6);

    assertThatThrownBy(() -> assessor.assess(signals)).isInstanceOf(RiskUnavailableException.class);
  }

  @Test
  void workerThreadsSurviveFailuresAndReportThemOnlyAsMetrics() throws Exception {
    // 线上是真线程池：任务里的异常出在工作线程上，没有调用方可以兜住。这里用真线程池，并记录工作线程上有没有冒出未捕获的异常
    final List<Throwable> uncaught = java.util.Collections.synchronizedList(new ArrayList<>());
    final ThreadPoolExecutor executor = new ThreadPoolExecutor(2, 2, 0, TimeUnit.SECONDS,
        new ArrayBlockingQueue<>(100), runnable -> {
      final Thread thread = new Thread(runnable);
      thread.setUncaughtExceptionHandler((ignored, throwable) -> uncaught.add(throwable));
      return thread;
    });

    final FaultTolerantRedisClusterClient brokenCluster = mock(FaultTolerantRedisClusterClient.class);
    when(brokenCluster.withCluster(any())).thenThrow(new RuntimeException("connection refused"));
    final RegistrationRiskAssessor assessor = RegistrationRiskAssessor.create(new TestRiskConfig().build(),
        brokenCluster, clock, executor, meterRegistry, SourceNetworkClassifier.fromCidrBlocks(List.of()));

    for (int i = 0; i < 20; i++) {
      assessor.sessionCreated(signals(HOME_IP, number(i), ANDROID_UA, "s-" + i));
    }
    executor.shutdown();
    assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();

    assertThat(uncaught).as("a failure must never escape the worker thread").isEmpty();
    assertThat(count("error", "stage", "session", "kind", "unavailable")).isEqualTo(20);
  }

  @Test
  void aFullQueueDropsTheRecordInsteadOfBlocking() {
    final Executor fullQueue = task -> {
      throw new RejectedExecutionException("queue is full");
    };
    final RegistrationRiskAssessor assessor = RegistrationRiskAssessor.create(new TestRiskConfig().build(),
        REDIS_CLUSTER_EXTENSION.getRedisCluster(), clock, fullQueue, meterRegistry,
        SourceNetworkClassifier.fromCidrBlocks(List.of()));
    final RiskSignals signals = signals(HOME_IP, number(1), ANDROID_UA, "s");

    assertThatCode(() -> {
      assessor.sessionCreated(signals);
      assessor.codeRequested(signals);
      assessor.codeSent(signals);
      assessor.codeChecked(signals, false);
    }).doesNotThrowAnyException();

    assertThat(count("error", "kind", "dropped")).isEqualTo(4);
    assertThat(logEvents(Level.WARN)).as("rate limited").hasSize(1);
    assertThat(redisContents()).isEmpty();
  }

  @Test
  void recordsAboveThePerSecondLimitAreDroppedSoAnAttackCannotFillRedis() {
    final TestRiskConfig config = new TestRiskConfig();
    config.maxRecordsPerSecond = 3;
    final RegistrationRiskAssessor assessor = assessor(config);

    for (int i = 1; i <= 5; i++) {
      createSession(assessor, "198.51." + i + ".1", number(i));
    }

    assertThat(count("assessment", "stage", "session")).as("only 3 are recorded this second").isEqualTo(3);
    assertThat(count("error", "stage", "session", "kind", "rateLimited")).isEqualTo(2);
    assertThat(redisContents().keySet()).as("nothing was written to Redis for the two that were shed")
        .filteredOn(key -> key.startsWith("regrisk::num-sess::")).hasSize(3);
    assertThat(logEvents(Level.WARN)).as("one rate limited warning").hasSize(1);

    // 下一秒重新算
    clock.pin(clock.instant().plusSeconds(1));
    createSession(assessor, "198.51.9.1", number(9));
    assertThat(count("assessment", "stage", "session")).isEqualTo(4);
  }

  @Test
  void anUnexpectedErrorInsideTheAssessmentIsSwallowedAndCountedAsInternal() {
    final SourceNetworkClassifier broken = new SourceNetworkClassifier() {
      @Override
      public SourceNetwork classify(final String sourceAddress) {
        throw new IllegalStateException("bug in a classifier");
      }

      @Override
      public int networkCount() {
        return 0;
      }
    };
    final RegistrationRiskAssessor assessor = RegistrationRiskAssessor.create(new TestRiskConfig().build(),
        REDIS_CLUSTER_EXTENSION.getRedisCluster(), clock, Runnable::run, meterRegistry, broken);

    assertThatCode(() -> assessor.sessionCreated(signals(HOME_IP, number(1), ANDROID_UA, "s")))
        .doesNotThrowAnyException();

    assertThat(count("error", "stage", "session", "kind", "internal")).isEqualTo(1);
    assertThat(logEvents(Level.ERROR)).hasSize(1);
  }

  @Test
  @Timeout(value = 60, unit = TimeUnit.SECONDS)
  void aStuckRedisNeverBlocksTheCallerAndTheOverflowIsDropped() throws Exception {
    final CountDownLatch redisIsStuck = new CountDownLatch(1);
    final CountDownLatch firstTaskStarted = new CountDownLatch(1);
    final FaultTolerantRedisClusterClient stuckCluster = mock(FaultTolerantRedisClusterClient.class);
    when(stuckCluster.withCluster(any())).thenAnswer(invocation -> {
      firstTaskStarted.countDown();
      redisIsStuck.await();
      throw new RuntimeException("timed out");
    });

    // 1 个线程、队列 2：和线上一样是有界队列，满了抛 RejectedExecutionException
    final ThreadPoolExecutor executor =
        new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(2));

    try {
      final RegistrationRiskAssessor assessor = RegistrationRiskAssessor.create(new TestRiskConfig().build(), stuckCluster,
          clock, executor, meterRegistry, SourceNetworkClassifier.fromCidrBlocks(List.of()));

      final long start = System.nanoTime();
      assessor.sessionCreated(signals(HOME_IP, number(1), ANDROID_UA, "s-0"));
      assertThat(firstTaskStarted.await(10, TimeUnit.SECONDS)).isTrue();
      for (int i = 1; i < 10; i++) {
        assessor.sessionCreated(signals(HOME_IP, number(i + 1), ANDROID_UA, "s-" + i));
      }
      final Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

      // 第一个任务卡在 Redis 里；后面 2 个排队；其余 7 个被丢弃。整个过程调用方一点都没等
      assertThat(elapsed).isLessThan(Duration.ofSeconds(2));
      assertThat(count("error", "stage", "session", "kind", "dropped")).isEqualTo(7);
    } finally {
      redisIsStuck.countDown();
      executor.shutdown();
      assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
    }
  }

  // 隐私：键、值、指标标签、日志里都没有号码 / IP / 会话号原文

  @Test
  void nothingSensitiveEndsUpInRedisMetricsOrLogs() {
    final String ip = "203.0.113.201";
    final String e164 = "+8613712345678";
    final String sessionId = "PII-SESSION-ID-abc123";
    final String userAgent = "Signal-Android/0.1.2 Android/34 Build/175101 pii-marker";
    final String[] sensitive = {ip, "203.0.113", e164, "13712345678", "1371234", "861371", sessionId, "abc123",
        "PII-SESSION", "pii-marker", userAgent};

    final TestRiskConfig config = new TestRiskConfig();
    config.datacenterNetworks = List.of("192.0.2.0/24");
    final RegistrationRiskAssessor assessor = assessor(config);

    final RiskSignals signals = new RiskSignals(ip, e164, userAgent, sessionId, true);
    assessor.sessionCreated(signals);
    assessor.codeRequested(signals);
    assessor.codeSent(RiskSignals.forSession(e164, sessionId));
    assessor.codeChecked(RiskSignals.forSession(e164, sessionId), true);
    assessor.sessionCreated(signals);
    assessor.codeRequested(signals);
    assessor.assess(signals);

    // 同时故意让一次失败也走一遍（失败日志里也不能有）
    final FaultTolerantRedisClusterClient brokenCluster = mock(FaultTolerantRedisClusterClient.class);
    when(brokenCluster.withCluster(any())).thenThrow(new RuntimeException("connection refused"));
    RegistrationRiskAssessor.create(config.build(), brokenCluster, clock, Runnable::run, meterRegistry,
        SourceNetworkClassifier.fromCidrBlocks(List.of())).sessionCreated(signals);

    // Redis：键和值
    final Map<String, String> redis = redisContents();
    assertThat(redis).isNotEmpty();
    redis.forEach((key, value) -> assertThat(key + "=" + value).doesNotContain(sensitive));

    // 指标：名字和所有标签
    final StringBuilder meters = new StringBuilder();
    for (final Meter meter : meterRegistry.getMeters()) {
      meters.append(meter.getId().getName());
      meter.getId().getTags().forEach(tag -> meters.append(' ').append(tag.getKey()).append('=').append(tag.getValue()));
      meters.append('\n');
    }
    assertThat(meters.toString()).contains(METER_PREFIX + "assessment").doesNotContain(sensitive);

    // 日志：每一条的消息、参数、异常
    assertThat(logAppender.list).isNotEmpty();
    for (final ILoggingEvent event : logAppender.list) {
      final StringBuilder text = new StringBuilder(event.getFormattedMessage());
      if (event.getThrowableProxy() != null) {
        text.append(' ').append(event.getThrowableProxy().getMessage());
      }
      assertThat(text.toString()).doesNotContain(sensitive);
    }
  }

  // 结构化日志的形状

  @Test
  void aWouldAllowAssessmentIsLoggedAtInfoAsKeyValuePairsWithoutIdentifiers() {
    final RegistrationRiskAssessor assessor = assessor();

    createSession(assessor, HOME_IP, number(1));

    assertThat(logEvents(Level.INFO)).singleElement().satisfies(event -> assertThat(event.getFormattedMessage())
        .isEqualTo("registration risk (record only): stage=session outcome=wouldAllow failed=none platform=android "
            + "push=false countryCode=86 network=unlisted userAgent=published subnetSessions24h=1 ipSessions24h=1 "
            + "numberSessions24h=1 numberCodes24h=0 prefixCodes1h=0 prefixVerified1h=0 wouldAllowThisHour=0 "
            + "cohortCodes1h=0 cohortVerified1h=0"));
  }

  @Test
  void aWouldChallengeAssessmentIsOnlyLoggedAtDebugBecauseItsVolumeIsUnbounded() {
    final RegistrationRiskAssessor assessor = assessor();

    assessor.sessionCreated(signals(HOME_IP, number(1), "curl/8", newSessionId()));

    assertThat(logEvents(Level.INFO)).isEmpty();
    assertThat(logEvents(Level.DEBUG)).singleElement().satisfies(event -> assertThat(event.getFormattedMessage())
        .contains("outcome=wouldChallenge failed=3 platform=unrecognized")
        .contains("userAgent=unrecognized"));
  }

  /// 把 Redis 里所有 `regrisk::` 键和值取出来（比较用）
  private Map<String, String> redisContents() {
    final FaultTolerantRedisClusterClient cluster = REDIS_CLUSTER_EXTENSION.getRedisCluster();
    final Map<String, String> contents = new HashMap<>();

    for (final String key : cluster.withCluster(connection -> connection.sync().keys("*"))) {
      contents.put(key, cluster.withCluster(connection -> connection.sync().get(key)));
    }
    return contents;
  }
}
