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
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.push.PushNotification;
import org.whispersystems.textsecuregcm.push.PushNotificationSender;
import org.whispersystems.textsecuregcm.push.SendPushNotificationResult;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/**
 * Tellomi: Huawei Push Kit (HMS) server API — OAuth2 client-credentials token, then
 * {@code POST https://push-api.cloud.huawei.com/v1/{appId}/messages:send} with a data (transparent) message.
 * Docs: https://developer.huawei.com/consumer/cn/doc/HMSCore-References/https-send-api-0000001050986197
 */
public class HuaweiPushSender implements PushNotificationSender {

  private static final Logger logger = LoggerFactory.getLogger(HuaweiPushSender.class);
  private static final String SEND_TIMER_NAME = "org.whispersystems.textsecuregcm.push.vendor.HuaweiPushSender.send";
  private static final Set<String> UNREGISTERED_CODES = Set.of("80300007", "80300010");   // invalid / unregistered token

  private record Token(String value, Instant expiresAt) {}

  private final HttpClient httpClient;
  private final Executor executor;
  private final String appId;
  private final String clientSecret;
  private final URI tokenEndpoint;
  private final URI sendEndpoint;
  private final AtomicReference<Token> cachedToken = new AtomicReference<>();

  public HuaweiPushSender(final Executor executor, final String appId, final String clientSecret,
      final URI tokenEndpoint, final URI sendEndpoint) {
    this.executor = executor;
    this.appId = appId;
    this.clientSecret = clientSecret;
    this.tokenEndpoint = tokenEndpoint;
    this.sendEndpoint = sendEndpoint;
    this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build();
  }

  public HuaweiPushSender(final Executor executor, final String appId, final String clientSecret) {
    this(executor, appId, clientSecret,
        URI.create("https://oauth-login.cloud.huawei.com/oauth2/v3/token"),
        URI.create("https://push-api.cloud.huawei.com/v1/" + appId + "/messages:send"));
  }

  @Override
  public CompletableFuture<SendPushNotificationResult> sendNotification(final PushNotification pushNotification) {
    final Timer.Sample sample = Timer.start();
    return accessToken().thenCompose(token -> {
      final Map<String, Object> message = Map.of(
          "validate_only", false,
          "message", Map.of(
              "data", VendorPushPayload.dataJson(pushNotification),
              "token", List.of(VendorPushToken.rawToken(pushNotification.deviceToken())),
              "android", Map.of(
                  "urgency", pushNotification.urgent() ? "HIGH" : "NORMAL",
                  "ttl", (pushNotification.ttl() != null ? pushNotification.ttl() : Duration.ofDays(7)).toSeconds() + "s")));
      final String body;
      try {
        body = SystemMapper.jsonMapper().writeValueAsString(message);
      } catch (final IOException e) {
        return CompletableFuture.failedFuture(e);
      }
      final HttpRequest request = HttpRequest.newBuilder(sendEndpoint)
          .timeout(Duration.ofSeconds(15))
          .header("Authorization", "Bearer " + token)
          .header("Content-Type", "application/json; charset=UTF-8")
          .POST(HttpRequest.BodyPublishers.ofString(body))
          .build();
      return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString());
    }).thenApplyAsync(response -> {
      sample.stop(Metrics.timer(SEND_TIMER_NAME));
      return parse(response);
    }, executor);
  }

  private CompletableFuture<String> accessToken() {
    final Token t = cachedToken.get();
    if (t != null && t.expiresAt().isAfter(Instant.now().plusSeconds(60))) {
      return CompletableFuture.completedFuture(t.value());
    }
    final String body = "grant_type=client_credentials&client_id=" + URLEncoder.encode(appId, StandardCharsets.UTF_8)
        + "&client_secret=" + URLEncoder.encode(clientSecret, StandardCharsets.UTF_8);
    final HttpRequest request = HttpRequest.newBuilder(tokenEndpoint)
        .timeout(Duration.ofSeconds(15))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(body))
        .build();
    return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()).thenApply(response -> {
      try {
        final JsonNode json = SystemMapper.jsonMapper().readTree(response.body());
        final String value = json.path("access_token").asText(null);
        if (response.statusCode() != 200 || value == null) {
          throw new IllegalStateException("HMS token endpoint: http=" + response.statusCode() + " error=" + json.path("error").asText(""));
        }
        final Token fresh = new Token(value, Instant.now().plusSeconds(json.path("expires_in").asLong(3600)));
        cachedToken.set(fresh);
        return value;
      } catch (final IOException e) {
        throw new IllegalStateException("HMS token endpoint: unparseable response", e);
      }
    });
  }

  static SendPushNotificationResult parse(final HttpResponse<String> response) {
    try {
      final JsonNode json = SystemMapper.jsonMapper().readTree(response.body());
      final String code = json.path("code").asText("");
      if (response.statusCode() == 200 && "80000000".equals(code)) {
        return new SendPushNotificationResult(true, Optional.empty(), false, Optional.empty());
      }
      // 80100000 = 部分成功；单 token 场景下按 msg 里的 illegal_tokens 判断
      final boolean unregistered = UNREGISTERED_CODES.contains(code)
          || ("80100000".equals(code) && json.path("msg").asText("").contains("illegal_tokens"));
      logger.warn("HMS Push rejected notification: http={} code={} msg={}", response.statusCode(), code, json.path("msg").asText(""));
      return new SendPushNotificationResult(false, Optional.of("huawei-" + code), unregistered, Optional.empty());
    } catch (final IOException e) {
      logger.warn("HMS Push unparseable response: http={}", response.statusCode());
      return new SendPushNotificationResult(false, Optional.of("huawei-http-" + response.statusCode()), false, Optional.empty());
    }
  }
}
