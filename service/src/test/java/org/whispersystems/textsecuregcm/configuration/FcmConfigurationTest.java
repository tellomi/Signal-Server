/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Map;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretStore;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretsModule;
import org.whispersystems.textsecuregcm.util.SystemMapper;

class FcmConfigurationTest {

  private static Validator validator;

  @BeforeAll
  static void setUp() {
    SecretsModule.INSTANCE.setSecretStore(
        new SecretStore(Map.of("fcm.credentials", new SecretString("{}"))));
    validator = Validation.buildDefaultValidatorFactory().getValidator();
  }

  private static FcmConfiguration parse(final String proxyYaml) throws Exception {
    return SystemMapper.yamlMapper().readValue("credentials: secret://fcm.credentials\n" + proxyYaml,
        FcmConfiguration.class);
  }

  @Test
  void noProxyIsValidAndOff() throws Exception {
    final FcmConfiguration configuration = parse("");
    assertThat(configuration.proxy()).isNull();
    assertThat(validator.validate(configuration)).isEmpty();
  }

  @Test
  void gocoShiliProxyIsValid() throws Exception {
    final FcmConfiguration configuration = parse("proxy:\n  host: 104.199.226.46\n  port: 3128\n");
    assertThat(validator.validate(configuration)).isEmpty();
    assertThat(configuration.proxy().host()).isEqualTo("104.199.226.46");
    assertThat(configuration.proxy().port()).isEqualTo(3128);
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "proxy:\n  host: 104.199.226.46\n",
      "proxy:\n  host: 104.199.226.46\n  port: 0\n",
      "proxy:\n  host: 104.199.226.46\n  port: 70000\n",
      "proxy:\n  host: ''\n  port: 3128\n",
      "proxy:\n  host: '  '\n  port: 3128\n",
      "proxy:\n  port: 3128\n",
  })
  void invalidProxyIsRejected(final String proxyYaml) throws Exception {
    assertThat(validator.validate(parse(proxyYaml))).isNotEmpty();
  }
}
