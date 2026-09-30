/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import static org.assertj.core.api.Assertions.assertThat;

import com.vdurmont.semver4j.Semver;
import java.net.InetAddress;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.configuration.RegistrationRiskConfiguration;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.Condition;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.Reason;
import org.whispersystems.textsecuregcm.registration.risk.RiskRules.UserAgentClass;
import org.whispersystems.textsecuregcm.registration.risk.SourceNetworkClassifier.SourceNetwork;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;

/// ADR-0070 §6.1 第 1–4 条放行条件的判定：每一条单独、边界、互不遮挡。纯函数，不需要 Redis。
class RiskRulesTest {

  /// 小阈值，边界好数：网段 3、IP 2、号码 2、号段发码 4、号段转化率 ≥ 50%（≥ 4 条才判）、预算 3、这一组转化率 ≥ 50%（≥ 4 条才判）
  private static final RegistrationRiskConfiguration CONFIG = config();

  private static RegistrationRiskConfiguration config() {
    final TestRiskConfig config = new TestRiskConfig();
    config.maxSubnetSessionsPerDay = 3;
    config.maxIpSessionsPerDay = 2;
    config.maxNumberSessionsPerDay = 2;
    config.maxPrefixCodesPerHour = 4;
    config.minPrefixConversion = 0.5;
    config.minPrefixSamples = 4;
    config.globalHourlyBudget = 3;
    config.minCohortConversion = 0.5;
    config.minCohortSamples = 4;
    return config.build();
  }

  private static final RiskSnapshot QUIET = new RiskSnapshot(1, 1, 1, 0, 0, 0, 0, 0, 0);

  private static RiskAssessment evaluate(final RiskSnapshot snapshot) {
    return RiskRules.evaluate(snapshot, SourceNetwork.UNLISTED, UserAgentClass.PUBLISHED, CONFIG, true);
  }

  private static RiskSnapshot with(final long subnetSessions, final long ipSessions, final long numberSessions,
      final long numberCodes, final long prefixSent, final long prefixVerified, final long wouldAllowThisHour,
      final long cohortSent, final long cohortVerified) {

    return new RiskSnapshot(subnetSessions, ipSessions, numberSessions, numberCodes, prefixSent, prefixVerified,
        wouldAllowThisHour, cohortSent, cohortVerified);
  }

  @Test
  void quietSourceWouldBeAllowed() {
    final RiskAssessment assessment = evaluate(QUIET);

    assertThat(assessment.wouldAllow()).isTrue();
    assertThat(assessment.failedSignature()).isEqualTo("none");
    assertThat(assessment.conditions()).extracting(RiskAssessment.ConditionResult::condition)
        .containsExactly(Condition.FIRST_CODE, Condition.NOT_DATACENTER, Condition.NO_ANOMALY, Condition.BUDGET_HEALTHY);
    assertThat(assessment.failedConditions()).isEmpty();
  }

  // ① 只放行每个号码每天的第一条

  @Test
  void secondCodeToTheSameNumberFailsCondition1() {
    final RiskAssessment assessment = evaluate(with(1, 1, 1, 1, 0, 0, 0, 0, 0));

    assertThat(assessment.wouldAllow()).isFalse();
    assertThat(assessment.failedSignature()).isEqualTo("1");
    assertThat(assessment.result(Condition.FIRST_CODE).orElseThrow().failedReasons())
        .containsExactly(Reason.CODE_ALREADY_SENT);
  }

  // ② 机房 / 云厂商网段

  @ParameterizedTest
  @CsvSource({"DATACENTER,DATACENTER", "UNKNOWN,UNKNOWN_SOURCE"})
  void datacenterOrUnknownSourceFailsCondition2(final SourceNetwork network, final Reason reason) {
    final RiskAssessment assessment = RiskRules.evaluate(QUIET, network, UserAgentClass.PUBLISHED, CONFIG, true);

    assertThat(assessment.wouldAllow()).isFalse();
    assertThat(assessment.failedSignature()).isEqualTo("2");
    assertThat(assessment.result(Condition.NOT_DATACENTER).orElseThrow().failedReasons()).containsExactly(reason);
  }

  @Test
  void unlistedSourcePassesCondition2() {
    assertThat(evaluate(QUIET).result(Condition.NOT_DATACENTER).orElseThrow().passed()).isTrue();
  }

  // ③ 没有异常：每个阈值「等于上限」通过、「多 1」不通过

  private static long limit(final Reason reason) {
    return switch (reason) {
      case SUBNET_SESSIONS -> CONFIG.maxSubnetSessionsPerDay();
      case IP_SESSIONS -> CONFIG.maxIpSessionsPerDay();
      case NUMBER_SESSIONS -> CONFIG.maxNumberSessionsPerDay();
      case PREFIX_VOLUME -> CONFIG.maxPrefixCodesPerHour();
      default -> throw new IllegalArgumentException(reason.name());
    };
  }

  /// 只把被测的那一项设成 `value`，其余项都在正常范围内（号段发码数和验证成功数取同一个值，转化率 100%，不会顺带触发转化率）
  private static RiskSnapshot snapshotWith(final Reason reason, final long value) {
    return switch (reason) {
      case SUBNET_SESSIONS -> with(value, 1, 1, 0, 0, 0, 0, 0, 0);
      case IP_SESSIONS -> with(1, value, 1, 0, 0, 0, 0, 0, 0);
      case NUMBER_SESSIONS -> with(1, 1, value, 0, 0, 0, 0, 0, 0);
      case PREFIX_VOLUME -> with(1, 1, 1, 0, value, value, 0, 0, 0);
      default -> throw new IllegalArgumentException(reason.name());
    };
  }

  @ParameterizedTest
  @EnumSource(value = Reason.class, names = {"SUBNET_SESSIONS", "IP_SESSIONS", "NUMBER_SESSIONS", "PREFIX_VOLUME"})
  void countThresholdsAreInclusiveAtTheLimit(final Reason reason) {
    assertThat(evaluate(snapshotWith(reason, limit(reason))).wouldAllow()).as("at the limit").isTrue();

    // 再多 1 就是异常，而且只有这一个原因
    final RiskAssessment assessment = evaluate(snapshotWith(reason, limit(reason) + 1));
    assertThat(assessment.wouldAllow()).isFalse();
    assertThat(assessment.failedSignature()).isEqualTo("3");
    assertThat(assessment.result(Condition.NO_ANOMALY).orElseThrow().failedReasons()).containsExactly(reason);
  }

  @Test
  void prefixConversionNeedsEnoughSamples() {
    // 发了 3 条、一条没验对：样本不够（要 ≥ 4），不算转化率低
    assertThat(evaluate(with(1, 1, 1, 0, 3, 0, 0, 0, 0)).wouldAllow()).isTrue();

    // 发了 4 条、验对 1 条 = 25% < 50%
    final RiskAssessment low = evaluate(with(1, 1, 1, 0, 4, 1, 0, 0, 0));
    assertThat(low.result(Condition.NO_ANOMALY).orElseThrow().failedReasons()).containsExactly(Reason.PREFIX_CONVERSION);

    // 发了 4 条、验对 2 条 = 正好 50%，通过（下限是含的）
    assertThat(evaluate(with(1, 1, 1, 0, 4, 2, 0, 0, 0)).wouldAllow()).isTrue();
  }

  @Test
  void unrecognizedOrUnpublishedUserAgentIsAnAnomaly() {
    for (final Map.Entry<UserAgentClass, Reason> entry : Map.of(
        UserAgentClass.UNRECOGNIZED, Reason.USER_AGENT_UNRECOGNIZED,
        UserAgentClass.UNPUBLISHED, Reason.USER_AGENT_UNPUBLISHED).entrySet()) {

      final RiskAssessment assessment =
          RiskRules.evaluate(QUIET, SourceNetwork.UNLISTED, entry.getKey(), CONFIG, true);

      assertThat(assessment.failedSignature()).as(entry.getKey().name()).isEqualTo("3");
      assertThat(assessment.result(Condition.NO_ANOMALY).orElseThrow().failedReasons()).containsExactly(entry.getValue());
    }
  }

  // ④ 预算与转化率

  @Test
  void budgetIsUsedUpWhenThisHourAlreadyHasBudgetManyWouldAllows() {
    // 预算 3：本小时已经有 2 个「本来会放行」时这一个还有位置，有 3 个时就满了
    assertThat(evaluate(with(1, 1, 1, 0, 0, 0, 2, 0, 0)).wouldAllow()).isTrue();

    final RiskAssessment full = evaluate(with(1, 1, 1, 0, 0, 0, 3, 0, 0));
    assertThat(full.failedSignature()).isEqualTo("4");
    assertThat(full.result(Condition.BUDGET_HEALTHY).orElseThrow().failedReasons()).containsExactly(Reason.GLOBAL_BUDGET);
  }

  @Test
  void cohortConversionMustBeHealthy() {
    // 这一组发了 3 条、一条没验对：样本不够
    assertThat(evaluate(with(1, 1, 1, 0, 0, 0, 0, 3, 0)).wouldAllow()).isTrue();

    // 发了 4 条、验对 1 条 = 25% < 50%
    final RiskAssessment unhealthy = evaluate(with(1, 1, 1, 0, 0, 0, 0, 4, 1));
    assertThat(unhealthy.failedSignature()).isEqualTo("4");
    assertThat(unhealthy.result(Condition.BUDGET_HEALTHY).orElseThrow().failedReasons())
        .containsExactly(Reason.COHORT_CONVERSION);

    assertThat(evaluate(with(1, 1, 1, 0, 0, 0, 0, 4, 2)).wouldAllow()).isTrue();
  }

  @Test
  void beforeSendOnlyEvaluatesConditions1To3() {
    // 预算满了、这一组转化率也不健康，但发码前这一步没有第 4 条
    final RiskSnapshot snapshot = with(1, 1, 1, 0, 0, 0, 99, 10, 0);

    final RiskAssessment beforeSend =
        RiskRules.evaluate(snapshot, SourceNetwork.UNLISTED, UserAgentClass.PUBLISHED, CONFIG, false);

    assertThat(beforeSend.conditions()).extracting(RiskAssessment.ConditionResult::condition)
        .containsExactly(Condition.FIRST_CODE, Condition.NOT_DATACENTER, Condition.NO_ANOMALY);
    assertThat(beforeSend.wouldAllow()).isTrue();
    assertThat(beforeSend.result(Condition.BUDGET_HEALTHY)).isEmpty();
  }

  // 四条独立判定、不短路：「每条条件不满足的计数」才不会互相遮挡

  @Test
  void conditionsAreEvaluatedIndependently() {
    final RiskAssessment assessment = RiskRules.evaluate(with(9, 9, 9, 5, 9, 0, 9, 9, 0), SourceNetwork.DATACENTER,
        UserAgentClass.UNRECOGNIZED, CONFIG, true);

    assertThat(assessment.wouldAllow()).isFalse();
    assertThat(assessment.failedSignature()).isEqualTo("1+2+3+4");
    assertThat(assessment.result(Condition.NO_ANOMALY).orElseThrow().failedReasons()).containsExactlyInAnyOrder(
        Reason.SUBNET_SESSIONS, Reason.IP_SESSIONS, Reason.NUMBER_SESSIONS, Reason.PREFIX_VOLUME,
        Reason.PREFIX_CONVERSION, Reason.USER_AGENT_UNRECOGNIZED);
    assertThat(assessment.result(Condition.BUDGET_HEALTHY).orElseThrow().failedReasons())
        .containsExactlyInAnyOrder(Reason.GLOBAL_BUDGET, Reason.COHORT_CONVERSION);
  }

  @Test
  void failedSignatureListsOnlyTheFailedConditionsInOrder() {
    assertThat(RiskRules.evaluate(with(1, 1, 1, 1, 0, 0, 0, 0, 0), SourceNetwork.UNLISTED, UserAgentClass.UNPUBLISHED,
        CONFIG, true).failedSignature()).isEqualTo("1+3");
    assertThat(RiskRules.evaluate(QUIET, SourceNetwork.UNKNOWN, UserAgentClass.PUBLISHED, CONFIG, true)
        .failedSignature()).isEqualTo("2");
  }

  // User-Agent

  private static final Map<ClientPlatform, Set<Semver>> PUBLISHED_ANDROID = Map.of(
      ClientPlatform.ANDROID, Set.of(new Semver("0.1.2"), new Semver("0.1.3")));

  @ParameterizedTest
  @ValueSource(strings = {
      "Signal-Android/0.1.2 Android/34 Build/175101",
      "Signal-iOS/0.1.2 iOS/18.7 Build/9",
      "Signal-Desktop/0.1.10 Windows 11"})
  void anyStandardUserAgentIsPublishedWhenNoVersionsAreListed(final String userAgent) {
    assertThat(RiskRules.classifyUserAgent(userAgent, Map.of())).isEqualTo(UserAgentClass.PUBLISHED);
  }

  @Test
  void listedVersionsAreCheckedPerPlatform() {
    assertThat(RiskRules.classifyUserAgent("Signal-Android/0.1.2 Android/34 Build/175101", PUBLISHED_ANDROID))
        .isEqualTo(UserAgentClass.PUBLISHED);
    assertThat(RiskRules.classifyUserAgent("Signal-Android/0.1.3", PUBLISHED_ANDROID))
        .isEqualTo(UserAgentClass.PUBLISHED);
    assertThat(RiskRules.classifyUserAgent("Signal-Android/9.9.9 Android/34", PUBLISHED_ANDROID))
        .isEqualTo(UserAgentClass.UNPUBLISHED);
    // 只给 Android 列了版本：iOS 还是只看形状
    assertThat(RiskRules.classifyUserAgent("Signal-iOS/9.9.9 iOS/18.7", PUBLISHED_ANDROID))
        .isEqualTo(UserAgentClass.PUBLISHED);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "curl/8.4.0", "python-requests/2.32", "Mozilla/5.0 (X11; Linux x86_64)", "Signal-Android", "Signal-Android/notaversion",
      "Signal-Windows/1.0.0"})
  void everythingElseIsUnrecognized(final String userAgent) {
    assertThat(RiskRules.classifyUserAgent(userAgent, Map.of())).isEqualTo(UserAgentClass.UNRECOGNIZED);
  }

  // 来源地址、网段、号段

  @ParameterizedTest
  @CsvSource(delimiter = '|', value = {
      "203.0.113.77|203.0.113.0/24",
      " 203.0.113.77 |203.0.113.0/24",
      "2001:db8:1234:5678:9abc:def0:1234:5678|2001:db8:1234:5600::/56",
      "2001:DB8:1234:56FF:0:0:0:1|2001:db8:1234:5600::/56",
      "::ffff:203.0.113.77|203.0.113.0/24"})
  void subnetIsSlash24ForIpv4AndSlash56ForIpv6(final String address, final String subnet) {
    assertThat(RiskRules.subnetOf(RiskRules.parseAddress(address).orElseThrow())).isEqualTo(subnet);
  }

  @Test
  void neighboursInTheSameSubnetShareIt() {
    final InetAddress a = RiskRules.parseAddress("198.51.100.1").orElseThrow();
    final InetAddress b = RiskRules.parseAddress("198.51.100.254").orElseThrow();
    final InetAddress c = RiskRules.parseAddress("198.51.101.1").orElseThrow();

    assertThat(RiskRules.subnetOf(a)).isEqualTo(RiskRules.subnetOf(b)).isNotEqualTo(RiskRules.subnetOf(c));
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "example.com", "999.1.1.1", "localhost", "203.0.113.0/24", "fe80::1%eth0", "not an address"})
  void nonAddressesAreNotParsed(final String address) {
    assertThat(RiskRules.parseAddress(address)).isEmpty();
  }

  @ParameterizedTest
  @CsvSource({
      "+8613800138000,86:1380013",
      "+8618912345678,86:1891234",
      "+12025550123,1:2025550"})
  void segmentIsTheCountryCodeAndTheFirstSevenNationalDigits(final String e164, final String segment) {
    assertThat(RiskRules.segmentOf(e164)).contains(segment);
  }

  @Test
  void numbersOnTheSameSegmentShareIt() {
    assertThat(RiskRules.segmentOf("+8613800130000")).isEqualTo(RiskRules.segmentOf("+8613800139999"))
        .isNotEqualTo(RiskRules.segmentOf("+8613800140000"));
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "abc", "+", "13800138000", "+0"})
  void unparseableNumbersHaveNoSegment(final String e164) {
    assertThat(RiskRules.segmentOf(e164)).isEmpty();
  }

  @Test
  void lowConversionDoesNotDivideByZero() {
    assertThat(RiskRules.lowConversion(0, 0, 1, 0.5)).isFalse();
    assertThat(RiskRules.lowConversion(0, 0, 0, 0.5)).isFalse();
    assertThat(List.of(RiskRules.lowConversion(10, 10, 4, 0.5), RiskRules.lowConversion(10, 0, 4, 0.0)))
        .containsExactly(false, false);
  }
}
