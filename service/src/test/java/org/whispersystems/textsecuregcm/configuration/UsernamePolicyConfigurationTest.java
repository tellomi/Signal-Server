/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import io.dropwizard.jackson.Jackson;
import java.time.Duration;
import org.junit.jupiter.api.Test;

/** Tellomi (ADR-0066 §6.2, owner 2026-09-27): the rename cooldown is 180 days unless server.yml says otherwise. */
class UsernamePolicyConfigurationTest {

  // what Dropwizard parses server.yml with
  private static final ObjectMapper YAML = Jackson.newObjectMapper(new YAMLFactory());

  @Test
  void withoutRenameCooldownTheDefaultIs180Days() throws Exception {
    final UsernamePolicyConfiguration config = YAML.readValue("""
        denylistPath: /opt/signal/policy/username-hash-denylist.bin
        required: true
        """, UsernamePolicyConfiguration.class);

    assertEquals(Duration.ofDays(180), config.renameCooldown());
    assertEquals(Duration.ofDays(180), UsernamePolicyConfiguration.renameCooldown(config));
  }

  @Test
  void renameCooldownIsReadFromTheConfiguration() throws Exception {
    final UsernamePolicyConfiguration config = YAML.readValue("""
        denylistPath: /opt/signal/policy/username-hash-denylist.bin
        required: true
        renameCooldown: P30D
        """, UsernamePolicyConfiguration.class);

    assertEquals(Duration.ofDays(30), UsernamePolicyConfiguration.renameCooldown(config));
  }

  @Test
  void withoutAUsernamePolicyBlockTheDefaultStillApplies() {
    assertEquals(Duration.ofDays(180), UsernamePolicyConfiguration.renameCooldown(null));
  }

  @Test
  void aNegativeRenameCooldownIsRejected() {
    assertThrows(JsonMappingException.class, () -> YAML.readValue("""
        denylistPath: /opt/signal/policy/username-hash-denylist.bin
        required: true
        renameCooldown: -P1D
        """, UsernamePolicyConfiguration.class));
  }
}
