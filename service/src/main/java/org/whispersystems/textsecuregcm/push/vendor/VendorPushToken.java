/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push.vendor;

import java.util.Optional;
import org.whispersystems.textsecuregcm.push.PushNotification;

/**
 * Tellomi: mainland-China Android devices register vendor push tokens (Xiaomi Mi Push, Huawei HMS Push) through the
 * existing {@code PUT /v1/accounts/gcm/registration_id} endpoint, prefixed with the vendor name
 * ({@code xiaomi:<regId>}, {@code huawei:<token>}). Storing them in the FCM slot keeps the Device record and every
 * registration/sync path untouched; only dispatch looks at the prefix.
 */
public final class VendorPushToken {

  public static final String XIAOMI_PREFIX = "xiaomi:";
  public static final String HUAWEI_PREFIX = "huawei:";

  private VendorPushToken() {
  }

  /** The vendor token type encoded in a stored {@code gcmId}, if any. */
  public static Optional<PushNotification.TokenType> tokenType(final String gcmId) {
    if (gcmId == null) {
      return Optional.empty();
    }
    if (gcmId.startsWith(XIAOMI_PREFIX)) {
      return Optional.of(PushNotification.TokenType.XIAOMI);
    }
    if (gcmId.startsWith(HUAWEI_PREFIX)) {
      return Optional.of(PushNotification.TokenType.HUAWEI);
    }
    return Optional.empty();
  }

  /** The raw vendor token (prefix stripped). */
  public static String rawToken(final String gcmId) {
    final int i = gcmId.indexOf(':');
    return i < 0 ? gcmId : gcmId.substring(i + 1);
  }

  public static boolean isVendor(final PushNotification.TokenType type) {
    return type == PushNotification.TokenType.XIAOMI || type == PushNotification.TokenType.HUAWEI;
  }
}
