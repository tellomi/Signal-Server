/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.util.Map;
import org.junit.jupiter.api.Test;

class TellomiRegionTargetConfigTest {

  private final Validator validator = Validation.buildDefaultValidatorFactory().getValidator();

  private boolean valid(final Map<String, String> globalConfig) {
    return validator.validate(new RemoteConfigConfiguration(globalConfig)).isEmpty();
  }

  @Test
  void acceptsAbsentEmptyGlobalAndCn() {
    assertThat(valid(Map.of())).isTrue();
    assertThat(valid(Map.of("global.tellomi.region.target", ""))).isTrue();
    assertThat(valid(Map.of("global.tellomi.region.target", "global"))).isTrue();
    assertThat(valid(Map.of("global.tellomi.region.target", "cn"))).isTrue();
  }

  @Test
  void rejectsTypos() {
    assertThat(valid(Map.of("global.tellomi.region.target", "CN"))).isFalse();
    assertThat(valid(Map.of("global.tellomi.region.target", "china"))).isFalse();
  }
}
