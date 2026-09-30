/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.vdurmont.semver4j.Semver;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.util.InetAddressRange;

/// Tellomi（ADR-0070 §6.2、§6.3 第 1 步；tellomi/tellomi#1398 P2）：注册风控**只记录**。
///
/// 评估器算出「这次建会话本来会不会放行」并打指标 / 写结构化日志，**不改变任何用户可见的行为**（建会话照旧无条件要求验证码）。
/// 这里的阈值都只决定「本来会不会放行」的判定，P2 阶段没有任何一个会影响真实请求。
///
/// **整块缺省 = 不建评估器**（和上游一模一样，现网零风险）；**写了这一块 = 开**（`enabled` 缺省 true），
/// 要暂停但保留配置就写 `enabled: false`。这是静态配置，改了要重启（香港的 `dynamicConfig` 也是 `type: static` 内联，同样要重启）。
///
/// 所有阈值的缺省值都是**占位**：没有真实数据支撑，P2 收满数据后由 owner 定（见 PR 描述「需要 owner 决定」）。
///
/// @param enabled                    false = 保留配置但整体不跑；缺省 true
/// @param secret                     计数键的哈希密钥（HMAC-SHA256）。IP、号码、会话号都不以明文进 Redis；换密钥 = 计数清零（最多 24 小时的数据）
/// @param maxSubnetSessionsPerDay    同一网段（IPv4 /24、IPv6 /56）24 小时内建会话次数上限，超过 = 「网段异常」（§6.2 第 1 行）
/// @param maxIpSessionsPerDay        同一 IP 24 小时内建会话次数上限（运营商级 NAT 下一个 IP 背后可能是很多人，所以只影响「要不要放行」，从不拒绝）
/// @param maxNumberSessionsPerDay    同一号码 24 小时内建会话次数上限（§6.2 第 4 行）
/// @param maxPrefixCodesPerHour      同一号段（+86 号码的前 7 位）最近一小时发码数上限（§6.2 第 3 行）
/// @param minPrefixConversion        号段的「发码 → 验证成功」转化率下限（0–1）；发码数不足 `minPrefixSamples` 时不判
/// @param minPrefixSamples           判号段转化率所需的最少发码数
/// @param globalHourlyBudget         全局每小时「本来会放行」数的预算（§6.1 第 4 条、§6.2 最后一行）。P2 缺省很大，让
///                                   `wouldAllow` 反映「不受预算限制时的潜在放行量」；P3 小额放行时再调小
/// @param minCohortConversion        「本来会放行」那一组会话的发码 → 验证成功转化率下限（0–1，§6.1 第 4 条的「转化率健康」）
/// @param minCohortSamples           判这一组转化率所需的最少发码数
/// @param datacenterNetworks         机房 / 云厂商网段（CIDR，如 `203.0.113.0/24`，§6.1 第 2 条）。**缺省为空 = 这一条恒成立**；
///                                   数据来源和许可证等 owner 拍板，这一期不带任何数据文件
/// @param publishedClientVersions    已发布的客户端版本，按平台（android / ios / desktop）列出；某个平台没列 = 只查 User-Agent 的形状
/// @param workerThreads              后台评估线程数（评估不在请求线程上做）
/// @param queueCapacity              后台队列容量；满了就丢弃这一次记录（只记指标），绝不阻塞请求
/// @param maxRecordsPerSecond        每秒最多记录多少个事件，超过的丢弃（只记指标）。评估器往限流用的 Redis 里写键，攻击流量（大量不同的
///                                   IP / 号码建会话）下键数和攻击速率成正比，不设上限就可能挤占这套共享 Redis 的内存；正常注册量远低于此
public record RegistrationRiskConfiguration(@Nullable Boolean enabled,
                                            @NotNull SecretString secret,
                                            @Nullable Integer maxSubnetSessionsPerDay,
                                            @Nullable Integer maxIpSessionsPerDay,
                                            @Nullable Integer maxNumberSessionsPerDay,
                                            @Nullable Integer maxPrefixCodesPerHour,
                                            @Nullable Double minPrefixConversion,
                                            @Nullable Integer minPrefixSamples,
                                            @Nullable Integer globalHourlyBudget,
                                            @Nullable Double minCohortConversion,
                                            @Nullable Integer minCohortSamples,
                                            @Nullable List<String> datacenterNetworks,
                                            @Nullable Map<String, List<String>> publishedClientVersions,
                                            @Nullable Integer workerThreads,
                                            @Nullable Integer queueCapacity,
                                            @Nullable Integer maxRecordsPerSecond) {

  public static final int DEFAULT_MAX_SUBNET_SESSIONS_PER_DAY = 30;
  public static final int DEFAULT_MAX_IP_SESSIONS_PER_DAY = 5;
  public static final int DEFAULT_MAX_NUMBER_SESSIONS_PER_DAY = 5;
  public static final int DEFAULT_MAX_PREFIX_CODES_PER_HOUR = 30;
  public static final double DEFAULT_MIN_PREFIX_CONVERSION = 0.3;
  public static final int DEFAULT_MIN_PREFIX_SAMPLES = 20;
  public static final int DEFAULT_GLOBAL_HOURLY_BUDGET = 1_000;
  public static final double DEFAULT_MIN_COHORT_CONVERSION = 0.5;
  public static final int DEFAULT_MIN_COHORT_SAMPLES = 20;
  public static final int DEFAULT_WORKER_THREADS = 2;
  public static final int DEFAULT_QUEUE_CAPACITY = 512;
  public static final int DEFAULT_MAX_RECORDS_PER_SECOND = 20;

  /// `publishedClientVersions` 里允许的平台名（小写，对应 `ClientPlatform`）
  public static final Set<String> PLATFORMS = Set.of("android", "ios", "desktop");

  public RegistrationRiskConfiguration {
    if (enabled == null) {
      enabled = true;
    }
    maxSubnetSessionsPerDay = positive("maxSubnetSessionsPerDay", maxSubnetSessionsPerDay,
        DEFAULT_MAX_SUBNET_SESSIONS_PER_DAY);
    maxIpSessionsPerDay = positive("maxIpSessionsPerDay", maxIpSessionsPerDay, DEFAULT_MAX_IP_SESSIONS_PER_DAY);
    maxNumberSessionsPerDay = positive("maxNumberSessionsPerDay", maxNumberSessionsPerDay,
        DEFAULT_MAX_NUMBER_SESSIONS_PER_DAY);
    maxPrefixCodesPerHour = positive("maxPrefixCodesPerHour", maxPrefixCodesPerHour,
        DEFAULT_MAX_PREFIX_CODES_PER_HOUR);
    minPrefixConversion = ratio("minPrefixConversion", minPrefixConversion, DEFAULT_MIN_PREFIX_CONVERSION);
    minPrefixSamples = positive("minPrefixSamples", minPrefixSamples, DEFAULT_MIN_PREFIX_SAMPLES);
    globalHourlyBudget = positive("globalHourlyBudget", globalHourlyBudget, DEFAULT_GLOBAL_HOURLY_BUDGET);
    minCohortConversion = ratio("minCohortConversion", minCohortConversion, DEFAULT_MIN_COHORT_CONVERSION);
    minCohortSamples = positive("minCohortSamples", minCohortSamples, DEFAULT_MIN_COHORT_SAMPLES);
    workerThreads = positive("workerThreads", workerThreads, DEFAULT_WORKER_THREADS);
    queueCapacity = positive("queueCapacity", queueCapacity, DEFAULT_QUEUE_CAPACITY);
    maxRecordsPerSecond = positive("maxRecordsPerSecond", maxRecordsPerSecond, DEFAULT_MAX_RECORDS_PER_SECOND);
    if (workerThreads > 16) {
      throw new IllegalArgumentException("registrationRisk.workerThreads must be at most 16");
    }

    datacenterNetworks = datacenterNetworks == null ? List.of() : List.copyOf(datacenterNetworks);
    for (final String network : datacenterNetworks) {
      try {
        // 写错的网段（少了前缀长度、地址不合法……）在启动时就报出来，而不是悄悄少判一段
        new InetAddressRange(network);
      } catch (final IllegalArgumentException e) {
        throw new IllegalArgumentException("registrationRisk.datacenterNetworks has an invalid CIDR block: " + network, e);
      }
    }

    final Map<String, List<String>> versionsByPlatform = new HashMap<>();
    if (publishedClientVersions != null) {
      for (final Map.Entry<String, List<String>> entry : publishedClientVersions.entrySet()) {
        if (!PLATFORMS.contains(entry.getKey())) {
          throw new IllegalArgumentException(
              "registrationRisk.publishedClientVersions keys must be one of " + PLATFORMS + ": " + entry.getKey());
        }
        final List<String> versions = entry.getValue() == null ? List.of() : List.copyOf(entry.getValue());
        for (final String version : versions) {
          try {
            new Semver(version);
          } catch (final RuntimeException e) {
            throw new IllegalArgumentException(
                "registrationRisk.publishedClientVersions." + entry.getKey() + " has an invalid version: " + version, e);
          }
        }
        versionsByPlatform.put(entry.getKey(), versions);
      }
    }
    publishedClientVersions = Map.copyOf(versionsByPlatform);
  }

  private static int positive(final String name, @Nullable final Integer value, final int defaultValue) {
    if (value == null) {
      return defaultValue;
    }
    if (value < 1) {
      throw new IllegalArgumentException("registrationRisk." + name + " must be positive");
    }
    return value;
  }

  private static double ratio(final String name, @Nullable final Double value, final double defaultValue) {
    if (value == null) {
      return defaultValue;
    }
    if (value.isNaN() || value < 0 || value > 1) {
      throw new IllegalArgumentException("registrationRisk." + name + " must be within [0, 1]");
    }
    return value;
  }
}
