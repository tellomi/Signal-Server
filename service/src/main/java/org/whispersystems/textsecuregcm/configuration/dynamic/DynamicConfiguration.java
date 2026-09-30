/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration.dynamic;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonSetter;
import com.fasterxml.jackson.annotation.Nulls;
import jakarta.validation.Valid;
import java.math.BigDecimal;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.whispersystems.textsecuregcm.limits.RateLimiterConfig;

public class DynamicConfiguration {

  @JsonProperty
  @Valid
  private Map<String, DynamicExperimentEnrollmentConfiguration> experiments = Collections.emptyMap();

  @JsonProperty
  @Valid
  private Map<String, DynamicE164ExperimentEnrollmentConfiguration> e164Experiments = Collections.emptyMap();

  @JsonProperty
  @Valid
  private Map<String, RateLimiterConfig> limits = new HashMap<>();

  // Tellomi（tellomi/tellomi#1399）：`remoteDeprecation:` 只写键、没有内容（比如子项全被注释掉）时，YAML 给的是 null，
  // Jackson 会把字段覆盖成 null，过滤器在每个请求上读它就是 NPE；配置可以在线热更之后，这是一次手滑就全站 500。
  // SKIP = 显式的 null 不覆盖缺省值，效果等同于没写这一块
  @JsonProperty
  @JsonSetter(nulls = Nulls.SKIP)
  @Valid
  private DynamicRemoteDeprecationConfiguration remoteDeprecation = DynamicRemoteDeprecationConfiguration.DEFAULT;

  @JsonProperty
  @Valid
  private DynamicPaymentsConfiguration payments = DynamicPaymentsConfiguration.DEFAULT;

  @JsonProperty
  @Valid
  private DynamicCaptchaConfiguration captcha = new DynamicCaptchaConfiguration();

  @JsonProperty
  @Valid
  DynamicMessagePersisterConfiguration messagePersister = new DynamicMessagePersisterConfiguration();

  @JsonProperty
  @Valid
  DynamicMessageDeliveryConfiguration messageDelivery = new DynamicMessageDeliveryConfiguration();

  @JsonProperty
  @Valid
  DynamicRegistrationConfiguration registrationConfiguration = new DynamicRegistrationConfiguration(false);

  @JsonProperty
  @Valid
  DynamicMetricsConfiguration metricsConfiguration = new DynamicMetricsConfiguration(false, false);

  @JsonProperty
  @Valid
  List<Integer> svr2StatusCodesToIgnoreForAccountDeletion = Collections.emptyList();

  @JsonProperty
  @Valid
  List<Integer> svrbStatusCodesToIgnoreForAccountDeletion = Collections.emptyList();

  @JsonProperty
  @Valid
  DynamicRestDeprecationConfiguration restDeprecation = new DynamicRestDeprecationConfiguration(Map.of());

  @JsonProperty
  @Valid
  private DynamicCarrierDataLookupConfiguration carrierDataLookup = new DynamicCarrierDataLookupConfiguration();

  @JsonProperty
  @Valid
  private DynamicGrpcAllowListConfiguration grpcAllowList = new DynamicGrpcAllowListConfiguration();

  @JsonProperty
  @Valid
  private DynamicOmnibusConfiguration omnibus = new DynamicOmnibusConfiguration(BigDecimal.ZERO);

  @JsonProperty
  @Valid
  private DynamicTurnConfiguration turn = new DynamicTurnConfiguration();

  @JsonProperty
  @Valid
  private DynamicLoginPurchaseConfiguration loginPurchase = new DynamicLoginPurchaseConfiguration(false);

  public Optional<DynamicExperimentEnrollmentConfiguration> getExperimentEnrollmentConfiguration(
      final String experimentName) {
    return Optional.ofNullable(experiments.get(experimentName));
  }

  public Optional<DynamicE164ExperimentEnrollmentConfiguration> getE164ExperimentEnrollmentConfiguration(
      final String experimentName) {
    return Optional.ofNullable(e164Experiments.get(experimentName));
  }

  public Map<String, RateLimiterConfig> getLimits() {
    return limits;
  }

  public DynamicRemoteDeprecationConfiguration getRemoteDeprecationConfiguration() {
    return remoteDeprecation;
  }

  public DynamicPaymentsConfiguration getPaymentsConfiguration() {
    return payments;
  }

  public DynamicCaptchaConfiguration getCaptchaConfiguration() {
    return captcha;
  }

  public DynamicMessagePersisterConfiguration getMessagePersisterConfiguration() {
    return messagePersister;
  }

  public DynamicMessageDeliveryConfiguration getMessageDeliveryConfiguration() {
    return messageDelivery;
  }

  public DynamicRegistrationConfiguration getRegistrationConfiguration() {
    return registrationConfiguration;
  }

  public DynamicMetricsConfiguration getMetricsConfiguration() {
    return metricsConfiguration;
  }

  public List<Integer> getSvr2StatusCodesToIgnoreForAccountDeletion() {
    return svr2StatusCodesToIgnoreForAccountDeletion;
  }

  public List<Integer> getSvrbStatusCodesToIgnoreForAccountDeletion() {
    return svrbStatusCodesToIgnoreForAccountDeletion;
  }

  public DynamicRestDeprecationConfiguration restDeprecation() {
    return restDeprecation;
  }

  public DynamicCarrierDataLookupConfiguration getCarrierDataLookupConfiguration() {
    return carrierDataLookup;
  }

  public DynamicGrpcAllowListConfiguration getGrpcAllowList() {
    return grpcAllowList;
  }

  public DynamicOmnibusConfiguration getOmnibus() {
    return omnibus;
  }

  public DynamicTurnConfiguration getTurnConfiguration() {
    return turn;
  }

  public DynamicLoginPurchaseConfiguration getLoginPurchaseConfiguration() {
    return loginPurchase;
  }
}
