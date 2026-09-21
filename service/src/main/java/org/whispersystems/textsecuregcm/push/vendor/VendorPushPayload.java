/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push.vendor;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.UncheckedIOException;
import java.util.Map;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/** Same key/value contract as {@link org.whispersystems.textsecuregcm.push.FcmSender} so the Android client can reuse its FCM handler. */
final class VendorPushPayload {

  private VendorPushPayload() {
  }

  static Map<String, String> dataOf(final PushNotification pushNotification) {
    final String key = switch (pushNotification.notificationType()) {
      case NOTIFICATION -> "newMessageAlert";
      case ATTEMPT_LOGIN_NOTIFICATION_HIGH_PRIORITY -> "attemptLoginContext";
      case CHALLENGE -> "challenge";
      case RATE_LIMIT_CHALLENGE -> "rateLimitChallenge";
      case VERIFICATION_CODE_REQUESTED -> "verificationCodeRequested";
    };
    final String data = switch (pushNotification.notificationType()) {
      case VERIFICATION_CODE_REQUESTED -> {
        // 与 FcmSender 同：data 是 push 包私有的 VerificationCodeRequestData record，直接序列化
        try {
          yield SystemMapper.jsonMapper().writeValueAsString(pushNotification.data());
        } catch (final JsonProcessingException e) {
          throw new UncheckedIOException(e);
        }
      }
      default -> pushNotification.data() != null ? pushNotification.data().toString() : "";
    };
    return Map.of(key, data);
  }

  static String dataJson(final PushNotification pushNotification) {
    try {
      return SystemMapper.jsonMapper().writeValueAsString(dataOf(pushNotification));
    } catch (final JsonProcessingException e) {
      throw new UncheckedIOException(e);
    }
  }
}
