/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.exc.ValueInstantiationException;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretStore;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretsModule;
import org.whispersystems.textsecuregcm.util.SystemMapper;

class RegistrationRiskConfigurationTest {

  @BeforeAll
  static void setUpSecretStore() {
    SecretsModule.INSTANCE.setSecretStore(
        new SecretStore(Map.of("registrationRisk.secret", new SecretString("some-secret"))));
  }

  private static RegistrationRiskConfiguration parse(final String yaml) throws Exception {
    return SystemMapper.yamlMapper().readValue(yaml, RegistrationRiskConfiguration.class);
  }

  /// 只给密钥：其余全是缺省值（这些缺省值和 PR 描述「需要 owner 决定」一节里写的一致）
  @Test
  void defaults() throws Exception {
    final RegistrationRiskConfiguration configuration = parse("secret: secret://registrationRisk.secret\n");

    assertThat(configuration.enabled()).as("the block being present means on").isTrue();
    assertThat(configuration.secret().value()).isEqualTo("some-secret");
    assertThat(configuration.maxSubnetSessionsPerDay()).isEqualTo(30);
    assertThat(configuration.maxIpSessionsPerDay()).isEqualTo(5);
    assertThat(configuration.maxNumberSessionsPerDay()).isEqualTo(5);
    assertThat(configuration.maxPrefixCodesPerHour()).isEqualTo(30);
    assertThat(configuration.minPrefixConversion()).isEqualTo(0.3);
    assertThat(configuration.minPrefixSamples()).isEqualTo(20);
    assertThat(configuration.globalHourlyBudget()).isEqualTo(1_000);
    assertThat(configuration.minCohortConversion()).isEqualTo(0.5);
    assertThat(configuration.minCohortSamples()).isEqualTo(20);
    assertThat(configuration.datacenterNetworks()).as("empty list: condition 2 always holds").isEmpty();
    assertThat(configuration.publishedClientVersions()).isEmpty();
    assertThat(configuration.workerThreads()).isEqualTo(2);
    assertThat(configuration.queueCapacity()).isEqualTo(512);
    assertThat(configuration.maxRecordsPerSecond()).isEqualTo(20);
  }

  @Test
  void everythingCanBeConfigured() throws Exception {
    final RegistrationRiskConfiguration configuration = parse("""
        enabled: false
        secret: secret://registrationRisk.secret
        maxSubnetSessionsPerDay: 50
        maxIpSessionsPerDay: 8
        maxNumberSessionsPerDay: 9
        maxPrefixCodesPerHour: 70
        minPrefixConversion: 0.4
        minPrefixSamples: 10
        globalHourlyBudget: 25
        minCohortConversion: 0.6
        minCohortSamples: 12
        datacenterNetworks:
          - 203.0.113.0/24
          - 2001:db8::/32
        publishedClientVersions:
          android: ["0.1.2", "0.1.3"]
          ios: ["0.1.2"]
        workerThreads: 4
        queueCapacity: 100
        maxRecordsPerSecond: 7
        """);

    assertThat(configuration.enabled()).isFalse();
    assertThat(configuration.maxSubnetSessionsPerDay()).isEqualTo(50);
    assertThat(configuration.maxIpSessionsPerDay()).isEqualTo(8);
    assertThat(configuration.maxNumberSessionsPerDay()).isEqualTo(9);
    assertThat(configuration.maxPrefixCodesPerHour()).isEqualTo(70);
    assertThat(configuration.minPrefixConversion()).isEqualTo(0.4);
    assertThat(configuration.minPrefixSamples()).isEqualTo(10);
    assertThat(configuration.globalHourlyBudget()).isEqualTo(25);
    assertThat(configuration.minCohortConversion()).isEqualTo(0.6);
    assertThat(configuration.minCohortSamples()).isEqualTo(12);
    assertThat(configuration.datacenterNetworks()).containsExactly("203.0.113.0/24", "2001:db8::/32");
    assertThat(configuration.publishedClientVersions())
        .containsOnly(Map.entry("android", List.of("0.1.2", "0.1.3")), Map.entry("ios", List.of("0.1.2")));
    assertThat(configuration.workerThreads()).isEqualTo(4);
    assertThat(configuration.queueCapacity()).isEqualTo(100);
    assertThat(configuration.maxRecordsPerSecond()).isEqualTo(7);
  }

  @Test
  void theSecretIsRequired() {
    final Set<ConstraintViolation<RegistrationRiskConfiguration>> violations = Validation.buildDefaultValidatorFactory()
        .getValidator()
        .validate(new RegistrationRiskConfiguration(null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null));

    assertThat(violations).extracting(violation -> violation.getPropertyPath().toString()).containsExactly("secret");
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "maxSubnetSessionsPerDay: 0",
      "maxIpSessionsPerDay: -1",
      "maxNumberSessionsPerDay: 0",
      "maxPrefixCodesPerHour: 0",
      "minPrefixSamples: 0",
      "globalHourlyBudget: 0",
      "minCohortSamples: 0",
      "workerThreads: 0",
      "workerThreads: 17",
      "queueCapacity: 0",
      "maxRecordsPerSecond: 0",
      "minPrefixConversion: -0.1",
      "minPrefixConversion: 1.1",
      "minCohortConversion: 2"})
  void nonsenseNumbersAreRejectedAtStartup(final String line) {
    assertThatThrownBy(() -> parse("secret: secret://registrationRisk.secret\n" + line + "\n"))
        .isInstanceOf(ValueInstantiationException.class)
        .hasMessageContaining("registrationRisk.");
  }

  @ParameterizedTest
  @ValueSource(strings = {"203.0.113.0", "203.0.113.0/33", "999.0.0.0/8", "2001:db8::/129", "example.com/24", "203.0.113.0/x"})
  void aMalformedNetworkStopsTheServerInsteadOfSilentlyJudgingLess(final String network) {
    assertThatThrownBy(() -> parse("secret: secret://registrationRisk.secret\ndatacenterNetworks: ['" + network + "']\n"))
        .isInstanceOf(ValueInstantiationException.class)
        .hasMessageContaining("registrationRisk.datacenterNetworks")
        .hasMessageContaining(network);
  }

  @ParameterizedTest
  @ValueSource(strings = {"windows: ['1.0.0']", "Android: ['0.1.2']", "IOS: ['0.1.2']", "android: ['not-a-version']",
      "android: ['0.1']"})
  void unknownPlatformsAndBadVersionsAreRejected(final String line) {
    assertThatThrownBy(() -> parse("secret: secret://registrationRisk.secret\npublishedClientVersions:\n  " + line + "\n"))
        .isInstanceOf(ValueInstantiationException.class)
        .hasMessageContaining("registrationRisk.publishedClientVersions");
  }

  @Test
  void aPlatformWithNoListedVersionsMeansShapeOnly() throws Exception {
    final RegistrationRiskConfiguration configuration = parse("secret: secret://registrationRisk.secret\npublishedClientVersions:\n  android:\n");

    assertThat(configuration.publishedClientVersions()).containsEntry("android", List.of());
  }

  @Test
  void collectionsAreImmutableCopies() {
    final List<String> networks = new ArrayList<>(List.of("203.0.113.0/24"));
    final RegistrationRiskConfiguration configuration = new RegistrationRiskConfiguration(null,
        new SecretString("s"), null, null, null, null, null, null, null, null, null, networks, null, null, null, null);

    networks.add("198.51.100.0/24");

    assertThat(configuration.datacenterNetworks()).containsExactly("203.0.113.0/24");
    assertThatThrownBy(() -> configuration.datacenterNetworks().add("x")).isInstanceOf(UnsupportedOperationException.class);
  }
}
