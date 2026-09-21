/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push.vendor;

import java.util.Optional;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.textsecuregcm.push.PushNotificationSender;

/** Tellomi: the (optional) vendor push senders; a missing sender means that vendor is not configured. */
public record VendorPushSenders(@Nullable PushNotificationSender xiaomi, @Nullable PushNotificationSender huawei) {

  public static VendorPushSenders none() {
    return new VendorPushSenders(null, null);
  }

  public Optional<PushNotificationSender> forType(final PushNotification.TokenType tokenType) {
    return Optional.ofNullable(switch (tokenType) {
      case XIAOMI -> xiaomi;
      case HUAWEI -> huawei;
      default -> null;
    });
  }
}
