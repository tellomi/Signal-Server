/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.configuration;

import jakarta.validation.Valid;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/**
 * Tellomi: mainland-China vendor push channels (#941). Both blocks optional; an absent / disabled block means devices
 * that registered that vendor's token get no push (they fall back to the app's own websocket keep-alive).
 */
public record VendorPushConfiguration(@Nullable @Valid Xiaomi xiaomi, @Nullable @Valid Huawei huawei) {

  public record Xiaomi(boolean enabled, SecretString appSecret, String packageName) {}

  public record Huawei(boolean enabled, String appId, SecretString clientSecret) {}

  public static VendorPushConfiguration none() {
    return new VendorPushConfiguration(null, null);
  }
}
