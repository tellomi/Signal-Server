/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import java.util.List;
import java.util.Map;
import org.whispersystems.textsecuregcm.configuration.RegistrationRiskConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/// 测试里造 [RegistrationRiskConfiguration] 用的可变构造器：缺省值 = 线上缺省配置（除了每秒记录数，测试里放开，免得被上限误伤）。
/// 记录的参数是按位置传的，加字段时只改这一处。
public final class TestRiskConfig {

  public int maxSubnetSessionsPerDay = RegistrationRiskConfiguration.DEFAULT_MAX_SUBNET_SESSIONS_PER_DAY;
  public int maxIpSessionsPerDay = RegistrationRiskConfiguration.DEFAULT_MAX_IP_SESSIONS_PER_DAY;
  public int maxNumberSessionsPerDay = RegistrationRiskConfiguration.DEFAULT_MAX_NUMBER_SESSIONS_PER_DAY;
  public int maxPrefixCodesPerHour = RegistrationRiskConfiguration.DEFAULT_MAX_PREFIX_CODES_PER_HOUR;
  public double minPrefixConversion = RegistrationRiskConfiguration.DEFAULT_MIN_PREFIX_CONVERSION;
  public int minPrefixSamples = RegistrationRiskConfiguration.DEFAULT_MIN_PREFIX_SAMPLES;
  public int globalHourlyBudget = RegistrationRiskConfiguration.DEFAULT_GLOBAL_HOURLY_BUDGET;
  public double minCohortConversion = RegistrationRiskConfiguration.DEFAULT_MIN_COHORT_CONVERSION;
  public int minCohortSamples = RegistrationRiskConfiguration.DEFAULT_MIN_COHORT_SAMPLES;
  public List<String> datacenterNetworks = List.of();
  public Map<String, List<String>> publishedClientVersions = Map.of();
  public int maxRecordsPerSecond = 1_000_000;

  public RegistrationRiskConfiguration build() {
    return new RegistrationRiskConfiguration(true, new SecretString("secret"), maxSubnetSessionsPerDay,
        maxIpSessionsPerDay, maxNumberSessionsPerDay, maxPrefixCodesPerHour, minPrefixConversion, minPrefixSamples,
        globalHourlyBudget, minCohortConversion, minCohortSamples, datacenterNetworks, publishedClientVersions, null,
        null, maxRecordsPerSecond);
  }

  public static RegistrationRiskConfiguration defaults() {
    return new TestRiskConfig().build();
  }
}
