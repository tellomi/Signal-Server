/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.push;

import java.time.Duration;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.Device;

public record PushNotification(String deviceToken,
                               TokenType tokenType,
                               NotificationType notificationType,
                               @Nullable Object data,
                               @Nullable Account destination,
                               @Nullable Device destinationDevice,
                               boolean urgent,
                               @Nullable Duration ttl) {

  // APNs allows up to 30 days, but FCM allows a max of 28. See:
  //
  // - https://developer.apple.com/documentation/usernotifications/sending-notification-requests-to-apns
  // - https://firebase.google.com/docs/cloud-messaging/customize-messages/setting-message-lifespan
  private static final Duration MAX_TTL = Duration.ofDays(28);

  public enum NotificationType {
    NOTIFICATION,
    ATTEMPT_LOGIN_NOTIFICATION_HIGH_PRIORITY,
    CHALLENGE,
    RATE_LIMIT_CHALLENGE,
    VERIFICATION_CODE_REQUESTED
  }

  public enum TokenType {
    FCM,
    APN,
    XIAOMI,   // Tellomi: 小米推送（token 存在 gcmId 槽，前缀 xiaomi:）
    HUAWEI    // Tellomi: 华为推送（前缀 huawei:）
  }

  public PushNotification {
    if (ttl != null && ttl.compareTo(MAX_TTL) > 0) {
      throw new IllegalArgumentException("TTL must not be longer than " + MAX_TTL);
    }
  }
}
