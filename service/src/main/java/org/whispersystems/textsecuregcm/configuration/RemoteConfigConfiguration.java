/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotNull;
import java.util.Map;
import java.util.Set;

public record RemoteConfigConfiguration(@NotNull Map<String, String> globalConfig) {

  /**
   * Tellomi (REGION_PROFILE §6.2): which region clients should move to. Absent / empty = feature off (clients stay on
   * global and do no failover). Clients only switch after a successful probe of the target, so a wrong value cannot
   * strand anyone, but a typo would silently mean "off" - reject it at startup instead.
   */
  public static final String TELLOMI_REGION_TARGET = "global.tellomi.region.target";

  static final Set<String> TELLOMI_REGION_TARGET_VALUES = Set.of("", "global", "cn");

  @JsonIgnore
  @AssertTrue(message = "global.tellomi.region.target must be empty, \"global\" or \"cn\"")
  public boolean isTellomiRegionTargetValid() {
    return globalConfig == null
        || !globalConfig.containsKey(TELLOMI_REGION_TARGET)
        || TELLOMI_REGION_TARGET_VALUES.contains(globalConfig.get(TELLOMI_REGION_TARGET));
  }
}
