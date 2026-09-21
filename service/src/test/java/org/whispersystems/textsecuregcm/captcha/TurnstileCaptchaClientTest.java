/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.captcha;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.configuration.TurnstileCaptchaConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

class TurnstileCaptchaClientTest {

  private static final String SITE_KEY = "0x4AAAAAAE_SiteKey";

  private HttpServer server;
  private final AtomicReference<String> nextBody = new AtomicReference<>();
  private final AtomicReference<Integer> nextStatus = new AtomicReference<>(200);
  private final AtomicReference<String> lastRequestBody = new AtomicReference<>();
  private TurnstileCaptchaClient client;

  @BeforeEach
  void setUp() throws IOException {
    server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    server.createContext("/siteverify", exchange -> {
      lastRequestBody.set(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
      final byte[] body = nextBody.get().getBytes(StandardCharsets.UTF_8);
      exchange.sendResponseHeaders(nextStatus.get(), body.length);
      exchange.getResponseBody().write(body);
      exchange.close();
    });
    server.start();

    final TurnstileCaptchaConfiguration configuration = new TurnstileCaptchaConfiguration(SITE_KEY,
        new SecretString("secret-key"), "http://127.0.0.1:" + server.getAddress().getPort() + "/siteverify", false);
    client = new TurnstileCaptchaClient(configuration, HttpClient.newHttpClient());
  }

  @AfterEach
  void tearDown() {
    server.stop(0);
  }

  @Test
  void schemeAndSiteKeys() {
    assertThat(client.scheme()).isEqualTo("turnstile");
    // CaptchaChecker lower-cases the site key parsed from the token
    assertThat(client.validSiteKeys(Action.REGISTRATION)).containsExactly(SITE_KEY.toLowerCase());
  }

  @Test
  void success() throws IOException {
    nextBody.set("{\"success\":true,\"action\":\"registration\",\"hostname\":\"chat.tellomi.app\",\"error-codes\":[]}");
    final AssessmentResult result = client.verify(Optional.empty(), SITE_KEY, Action.REGISTRATION, "0.tok.en", "1.2.3.4", "ua");
    assertThat(result.isValid()).isTrue();
    assertThat(lastRequestBody.get()).contains("secret=secret-key").contains("response=0.tok.en").contains("remoteip=1.2.3.4");
  }

  @Test
  void rejected() throws IOException {
    nextBody.set("{\"success\":false,\"error-codes\":[\"invalid-input-response\"]}");
    assertThat(client.verify(Optional.empty(), SITE_KEY, Action.REGISTRATION, "bad", "1.2.3.4", null).isValid()).isFalse();
  }

  @Test
  void actionMismatch() throws IOException {
    nextBody.set("{\"success\":true,\"action\":\"challenge\"}");
    assertThat(client.verify(Optional.empty(), SITE_KEY, Action.REGISTRATION, "tok", "1.2.3.4", null).isValid()).isFalse();
  }

  @Test
  void httpError() {
    nextBody.set("oops");
    nextStatus.set(502);
    assertThrows(IOException.class,
        () -> client.verify(Optional.empty(), SITE_KEY, Action.REGISTRATION, "tok", "1.2.3.4", null));
  }
}
