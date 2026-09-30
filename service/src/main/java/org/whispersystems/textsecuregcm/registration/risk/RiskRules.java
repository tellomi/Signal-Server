/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import com.google.common.net.InetAddresses;
import com.google.i18n.phonenumbers.NumberParseException;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import com.google.i18n.phonenumbers.Phonenumber;
import com.vdurmont.semver4j.Semver;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.configuration.RegistrationRiskConfiguration;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.Condition;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.ConditionResult;
import org.whispersystems.textsecuregcm.registration.risk.RiskAssessment.Reason;
import org.whispersystems.textsecuregcm.registration.risk.SourceNetworkClassifier.SourceNetwork;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;
import org.whispersystems.textsecuregcm.util.ua.UserAgent;
import org.whispersystems.textsecuregcm.util.ua.UserAgentUtil;

/// 放行条件的判定规则（ADR-0070 §6.1 第 1–4 条）：纯函数，不碰 Redis、时钟和指标，所以每一条都能单独测。
///
/// | 条 | 通过的条件 | 没通过的原因 |
/// | --- | --- | --- |
/// | ① | 这个号码 24 小时内还没收过我们的码 | `code-already-sent` |
/// | ② | 来源不是机房 / 云厂商网段 | `datacenter`；来源判不出来也不放行：`unknown-source` |
/// | ③ | 没有异常：网段 / IP / 号码的 24 小时会话数、号段 1 小时发码数与转化率、User-Agent 都正常（§6.2） | `subnet-sessions` `ip-sessions` `number-sessions` `prefix-volume` `prefix-conversion` `ua-unrecognized` `ua-unpublished` |
/// | ④ | 全局本小时「本来会放行」数没超预算，且这一组会话的转化率健康 | `global-budget` `cohort-conversion` |
///
/// 四条都独立判定、不短路，这样「每条条件不满足的计数」互不遮挡。
final class RiskRules {

  /// 号段 = 号码的前 7 位（不含国家码）。中国手机号 11 位，前 7 位就是运营商查归属地用的「号段」
  static final int SEGMENT_DIGITS = 7;

  private static final PhoneNumberUtil PHONE_NUMBER_UTIL = PhoneNumberUtil.getInstance();

  private RiskRules() {
  }

  /// User-Agent 的分类（§6.2 第 5 行）
  enum UserAgentClass {
    /// 是 `Signal-<平台>/<版本> …` 的形状；配置里给这个平台列了已发布版本的话，版本也在列表里
    PUBLISHED,
    /// 形状对，但版本不在配置里列出的已发布版本里
    UNPUBLISHED,
    /// 缺失，或者根本不是我们的客户端会发的 User-Agent（`curl/8`、`python-requests/2` 之类）
    UNRECOGNIZED;

    String tag() {
      return name().toLowerCase(Locale.ROOT);
    }
  }

  /// @param includeBudget true = 判 ①–④（建会话）；false = 只判 ①–③（发码前）
  static RiskAssessment evaluate(final RiskSnapshot snapshot,
      final SourceNetwork sourceNetwork,
      final UserAgentClass userAgentClass,
      final RegistrationRiskConfiguration config,
      final boolean includeBudget) {

    final List<ConditionResult> results = new ArrayList<>(4);

    // ① 只放行每个号码每天的第一条：这是「被拿来短信轰炸」的关键（§6.1）
    results.add(new ConditionResult(Condition.FIRST_CODE,
        snapshot.numberCodes24h() > 0 ? Set.of(Reason.CODE_ALREADY_SENT) : Set.of()));

    // ② 机房 / 云厂商网段
    results.add(new ConditionResult(Condition.NOT_DATACENTER, switch (sourceNetwork) {
      case DATACENTER -> Set.of(Reason.DATACENTER);
      case UNKNOWN -> Set.of(Reason.UNKNOWN_SOURCE);
      case UNLISTED -> Set.<Reason>of();
    }));

    // ③ 没有异常。这些只决定「要不要出验证」，不用来拒绝（运营商级 NAT，§2.1 第 4 点）
    final Set<Reason> anomalies = EnumSet.noneOf(Reason.class);
    if (snapshot.subnetSessions24h() > config.maxSubnetSessionsPerDay()) {
      anomalies.add(Reason.SUBNET_SESSIONS);
    }
    if (snapshot.ipSessions24h() > config.maxIpSessionsPerDay()) {
      anomalies.add(Reason.IP_SESSIONS);
    }
    if (snapshot.numberSessions24h() > config.maxNumberSessionsPerDay()) {
      anomalies.add(Reason.NUMBER_SESSIONS);
    }
    if (snapshot.prefixSent1h() > config.maxPrefixCodesPerHour()) {
      anomalies.add(Reason.PREFIX_VOLUME);
    }
    if (lowConversion(snapshot.prefixSent1h(), snapshot.prefixVerified1h(), config.minPrefixSamples(),
        config.minPrefixConversion())) {
      anomalies.add(Reason.PREFIX_CONVERSION);
    }
    switch (userAgentClass) {
      case UNRECOGNIZED -> anomalies.add(Reason.USER_AGENT_UNRECOGNIZED);
      case UNPUBLISHED -> anomalies.add(Reason.USER_AGENT_UNPUBLISHED);
      case PUBLISHED -> {
      }
    }
    results.add(new ConditionResult(Condition.NO_ANOMALY, anomalies));

    // ④ 预算与转化率
    if (includeBudget) {
      final Set<Reason> budget = EnumSet.noneOf(Reason.class);
      if (snapshot.wouldAllowThisHour() >= config.globalHourlyBudget()) {
        budget.add(Reason.GLOBAL_BUDGET);
      }
      if (lowConversion(snapshot.cohortSent1h(), snapshot.cohortVerified1h(), config.minCohortSamples(),
          config.minCohortConversion())) {
        budget.add(Reason.COHORT_CONVERSION);
      }
      results.add(new ConditionResult(Condition.BUDGET_HEALTHY, budget));
    }

    return new RiskAssessment(results);
  }

  /// 发码数够多（≥ `minSamples`）而验证成功率低于 `minRatio` 才算转化率低；样本不够不判（早期用户少，别把噪声当异常）
  static boolean lowConversion(final long sent, final long verified, final int minSamples, final double minRatio) {
    return sent >= Math.max(1, minSamples) && (double) verified / sent < minRatio;
  }

  /// 有配置该平台的已发布版本就要求版本在列表里；没配置就只看形状
  static UserAgentClass classifyUserAgent(@Nullable final String userAgentHeader,
      final Map<ClientPlatform, Set<Semver>> publishedVersions) {

    final UserAgent userAgent = UserAgentUtil.maybeParseUserAgentString(userAgentHeader);
    if (userAgent == null) {
      return UserAgentClass.UNRECOGNIZED;
    }

    final Set<Semver> published = publishedVersions.getOrDefault(userAgent.platform(), Set.of());
    if (published.isEmpty() || published.contains(userAgent.version())) {
      return UserAgentClass.PUBLISHED;
    }
    return UserAgentClass.UNPUBLISHED;
  }

  /// 解析来源地址；不是 IP 字面量（主机名、空串、带 scope 的地址……）返回空，绝不做 DNS 查询
  static Optional<InetAddress> parseAddress(@Nullable final String address) {
    if (address == null || address.isBlank()) {
      return Optional.empty();
    }
    try {
      return Optional.of(InetAddresses.forString(address.strip()));
    } catch (final IllegalArgumentException e) {
      return Optional.empty();
    }
  }

  /// 网段：IPv4 /24、IPv6 /56（和 ALTCHA 按网段升难度用的口径一致，§5.4）
  static String subnetOf(final InetAddress address) {
    final byte[] bytes = address.getAddress();
    final boolean ipv4 = bytes.length == 4;
    for (int i = ipv4 ? 3 : 7; i < bytes.length; i++) {
      bytes[i] = 0;
    }
    try {
      return InetAddresses.toAddrString(InetAddress.getByAddress(bytes)) + (ipv4 ? "/24" : "/56");
    } catch (final UnknownHostException e) {
      throw new AssertionError("an address of 4 or 16 bytes is always valid", e);
    }
  }

  /// 号段：`<国家码>:<全国号码的前 7 位>`，例如 `+8613800138000` → `86:1380013`。解析不了的号码返回空
  static Optional<String> segmentOf(final String e164) {
    try {
      final Phonenumber.PhoneNumber number = PHONE_NUMBER_UTIL.parse(e164, null);
      final String national = Long.toString(number.getNationalNumber());
      return Optional.of(number.getCountryCode() + ":" + national.substring(0, Math.min(SEGMENT_DIGITS, national.length())));
    } catch (final NumberParseException e) {
      return Optional.empty();
    }
  }
}
