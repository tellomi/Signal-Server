/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.push.vendor;

import com.fasterxml.jackson.databind.JsonNode;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Timer;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.textsecuregcm.push.PushNotificationSender;
import org.whispersystems.textsecuregcm.push.SendPushNotificationResult;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/**
 * Tellomi: Xiaomi Mi Push (小米推送) server API — {@code POST /v3/message/regid}, {@code Authorization: key=<appSecret>}.
 * We send pass-through (transparent) messages carrying the same data map as FCM, so the client's existing message
 * handler can be reused. Docs: https://dev.mi.com/console/doc/detail?pId=1163
 */
public class XiaomiPushSender implements PushNotificationSender {

  private static final Logger logger = LoggerFactory.getLogger(XiaomiPushSender.class);
  private static final String SEND_TIMER_NAME = "org.whispersystems.textsecuregcm.push.vendor.XiaomiPushSender.send";
  private static final Duration DEFAULT_TTL = Duration.ofDays(7);   // Mi Push 上限 14 天

  /** Mi Push error codes that mean the registration id is gone for good. */
  private static final java.util.Set<Integer> UNREGISTERED_CODES = java.util.Set.of(10001, 10002, 20301, 21301, 22001);

  private final HttpClient httpClient;
  private final Executor executor;
  private final URI endpoint;
  private final String appSecret;
  private final String packageName;

  public XiaomiPushSender(final Executor executor, final String appSecret, final String packageName, final URI endpoint) {
    this.executor = executor;
    this.appSecret = appSecret;
    this.packageName = packageName;
    this.endpoint = endpoint;
    this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
  }

  public XiaomiPushSender(final Executor executor, final String appSecret, final String packageName) {
    this(executor, appSecret, packageName, URI.create("https://api.xmpush.xiaomi.com/v3/message/regid"));
  }

  @Override
  public CompletableFuture<SendPushNotificationResult> sendNotification(final PushNotification pushNotification) {
    final Map<String, String> form = new LinkedHashMap<>();
    form.put("registration_id", VendorPushToken.rawToken(pushNotification.deviceToken()));
    form.put("restricted_package_name", packageName);
    form.put("pass_through", "1");
    form.put("payload", VendorPushPayload.dataJson(pushNotification));
    form.put("time_to_live", Long.toString((pushNotification.ttl() != null ? pushNotification.ttl() : DEFAULT_TTL).toMillis()));
    // 透传消息不展示，也不用 notify_type；紧急与否由 payload 里的 key 决定，客户端自己出通知
    final String body = form.entrySet().stream()
        .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
        .collect(Collectors.joining("&"));

    final HttpRequest request = HttpRequest.newBuilder(endpoint)
        .timeout(Duration.ofSeconds(15))
        .header("Authorization", "key=" + appSecret)
        .header("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();

    final Timer.Sample sample = Timer.start();
    return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
        .thenApplyAsync(response -> {
          sample.stop(Metrics.timer(SEND_TIMER_NAME));
          return parse(response);
        }, executor);
  }

  static SendPushNotificationResult parse(final HttpResponse<String> response) {
    try {
      final JsonNode json = SystemMapper.jsonMapper().readTree(response.body());
      final int code = json.path("code").asInt(-1);
      final String result = json.path("result").asText("");
      if (response.statusCode() == 200 && code == 0 && "ok".equals(result)) {
        return new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty());
      }
      final boolean unregistered = UNREGISTERED_CODES.contains(code);
      logger.warn("Mi Push rejected notification: http={} code={} reason={}", response.statusCode(), code, json.path("reason").asText(""));
      return new SendPushNotificationResult(false, Optional.of("xiaomi-" + code), unregistered, Optional.empty());
    } catch (final IOException e) {
      logger.warn("Mi Push unparseable response: http={}", response.statusCode());
      return new SendPushNotificationResult(false, Optional.of("xiaomi-http-" + response.statusCode()), false, Optional.empty());
    }
  }
}
