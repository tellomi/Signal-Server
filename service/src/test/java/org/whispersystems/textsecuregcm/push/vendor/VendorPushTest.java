/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push.vendor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.http.HttpResponse;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.push.APNSender;
import org.whispersystems.textsecuregcm.push.FcmSender;
import org.whispersystems.textsecuregcm.push.NotPushRegisteredException;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.textsecuregcm.push.PushNotificationManager;
import org.whispersystems.textsecuregcm.push.PushNotificationScheduler;
import org.whispersystems.textsecuregcm.push.PushNotificationSender;
import org.whispersystems.textsecuregcm.push.SendPushNotificationResult;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.tests.util.AccountsHelper;

class VendorPushTest {

  @Test
  void tokenPrefixes() {
    assertEquals(Optional.of(PushNotification.TokenType.XIAOMI), VendorPushToken.tokenType("xiaomi:abc"));
    assertEquals(Optional.of(PushNotification.TokenType.HUAWEI), VendorPushToken.tokenType("huawei:abc"));
    assertEquals(Optional.empty(), VendorPushToken.tokenType("plain-fcm-token"));
    assertEquals(Optional.empty(), VendorPushToken.tokenType(null));
    assertEquals("abc:def", VendorPushToken.rawToken("xiaomi:abc:def"));
    assertEquals("fcm", VendorPushToken.rawToken("fcm"));
  }

  @Test
  void dispatchByPrefix() throws NotPushRegisteredException {
    final AccountsManager accountsManager = mock(AccountsManager.class);
    AccountsHelper.setupMockUpdate(accountsManager);
    final FcmSender fcmSender = mock(FcmSender.class);
    final PushNotificationSender xiaomi = mock(PushNotificationSender.class);
    when(xiaomi.sendNotification(any())).thenReturn(CompletableFuture.completedFuture(
        new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty())));

    final PushNotificationManager manager = new PushNotificationManager(accountsManager, mock(APNSender.class), fcmSender,
        new VendorPushSenders(xiaomi, null), mock(PushNotificationScheduler.class));

    final Account account = mock(Account.class);
    final Device device = mock(Device.class);
    when(device.getId()).thenReturn(Device.PRIMARY_ID);
    when(device.getGcmId()).thenReturn("xiaomi:reg-1");
    when(account.getDevice(Device.PRIMARY_ID)).thenReturn(Optional.of(device));

    manager.sendNewMessageNotification(account, Device.PRIMARY_ID, true);
    verify(xiaomi).sendNotification(new PushNotification("xiaomi:reg-1", PushNotification.TokenType.XIAOMI,
        PushNotification.NotificationType.NOTIFICATION, null, account, device, true, null));

    // 华为没配置 → 视为未注册
    when(device.getGcmId()).thenReturn("huawei:tok-1");
    assertThrows(NotPushRegisteredException.class, () -> manager.sendNewMessageNotification(account, Device.PRIMARY_ID, true));
  }

  @Test
  void payloadMatchesFcmContract() {
    final PushNotification n = new PushNotification("xiaomi:r", PushNotification.TokenType.XIAOMI,
        PushNotification.NotificationType.NOTIFICATION, null, null, null, true, null);
    assertEquals("{\"newMessageAlert\":\"\"}", VendorPushPayload.dataJson(n));
    final PushNotification c = new PushNotification("xiaomi:r", PushNotification.TokenType.XIAOMI,
        PushNotification.NotificationType.CHALLENGE, "tok", null, null, true, null);
    assertEquals("{\"challenge\":\"tok\"}", VendorPushPayload.dataJson(c));
  }

  @SuppressWarnings("unchecked")
  private static HttpResponse<String> response(final int status, final String body) {
    final HttpResponse<String> r = mock(HttpResponse.class);
    when(r.statusCode()).thenReturn(status);
    when(r.body()).thenReturn(body);
    return r;
  }

  @Test
  void xiaomiResponses() {
    assertTrue(XiaomiPushSender.parse(response(200, "{\"result\":\"ok\",\"code\":0,\"data\":{\"id\":\"1\"}}")).accepted());
    final SendPushNotificationResult bad = XiaomiPushSender.parse(response(200, "{\"result\":\"error\",\"code\":10001,\"reason\":\"invalid regid\"}"));
    assertFalse(bad.accepted()); assertTrue(bad.unregistered()); assertEquals(Optional.of("xiaomi-10001"), bad.errorCode());
    final SendPushNotificationResult throttled = XiaomiPushSender.parse(response(200, "{\"result\":\"error\",\"code\":10014}"));
    assertFalse(throttled.accepted()); assertFalse(throttled.unregistered());
    assertFalse(XiaomiPushSender.parse(response(502, "<html>")).accepted());
  }

  @Test
  void huaweiResponses() {
    assertTrue(HuaweiPushSender.parse(response(200, "{\"code\":\"80000000\",\"msg\":\"Success\",\"requestId\":\"1\"}")).accepted());
    final SendPushNotificationResult bad = HuaweiPushSender.parse(response(200, "{\"code\":\"80300007\",\"msg\":\"All tokens are invalid\"}"));
    assertFalse(bad.accepted()); assertTrue(bad.unregistered());
    final SendPushNotificationResult partial = HuaweiPushSender.parse(response(200,
        "{\"code\":\"80100000\",\"msg\":\"{\\\"success\\\":0,\\\"failure\\\":1,\\\"illegal_tokens\\\":[\\\"t\\\"]}\"}"));
    assertTrue(partial.unregistered());
    assertFalse(HuaweiPushSender.parse(response(200, "{\"code\":\"80300008\",\"msg\":\"quota\"}")).unregistered());
  }
}
