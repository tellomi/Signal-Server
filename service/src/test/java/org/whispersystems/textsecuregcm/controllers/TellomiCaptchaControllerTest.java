/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.WebTarget;
import jakarta.ws.rs.core.Response;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.whispersystems.textsecuregcm.captcha.Action;
import org.whispersystems.textsecuregcm.captcha.AltchaCaptchaClient;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestRemoteAddressFilterProvider;

@ExtendWith(DropwizardExtensionsSupport.class)
class TellomiCaptchaControllerTest {

  private static final String CLIENT_IP = "203.0.113.9";

  private final AltchaCaptchaClient altchaCaptchaClient = mock(AltchaCaptchaClient.class);

  private final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(new TestRemoteAddressFilterProvider(CLIENT_IP))
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new TellomiCaptchaController(altchaCaptchaClient))
      .build();

  @Test
  void challenge() throws Exception {
    when(altchaCaptchaClient.issueChallenge(any(), any(), any()))
        .thenReturn(new AltchaCaptchaClient.IssuedChallenge("{\"parameters\":{},\"signature\":\"ab\"}", 0, false));

    try (final Response response = resources.getJerseyTest().target("/v1/tellomi/captcha/altcha/challenge")
        .queryParam("action", "registration")
        .queryParam("via", "fallback-timeout")
        .request()
        .get()) {

      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getHeaderString("Cache-Control")).isEqualTo("no-store");
      assertThat(response.readEntity(String.class)).isEqualTo("{\"parameters\":{},\"signature\":\"ab\"}");
    }
    // 网段按真实来源地址算（nginx 覆盖过的 X-Forwarded-For → RemoteAddressFilter）
    verify(altchaCaptchaClient).issueChallenge(Action.REGISTRATION, CLIENT_IP, "fallback-timeout");
  }

  @Test
  void challengeAction() throws Exception {
    when(altchaCaptchaClient.issueChallenge(any(), any(), any()))
        .thenReturn(new AltchaCaptchaClient.IssuedChallenge("{}", 2, false));

    try (final Response response = resources.getJerseyTest().target("/v1/tellomi/captcha/altcha/challenge")
        .queryParam("action", "challenge")
        .request()
        .get()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verify(altchaCaptchaClient).issueChallenge(eq(Action.CHALLENGE), eq(CLIENT_IP), any());
  }

  @Test
  void unknownAction() throws Exception {
    for (final String action : new String[]{"login", ""}) {
      try (final Response response = resources.getJerseyTest().target("/v1/tellomi/captcha/altcha/challenge")
          .queryParam("action", action)
          .request()
          .get()) {
        assertThat(response.getStatus()).isEqualTo(400);
      }
    }
    try (final Response response = resources.getJerseyTest().target("/v1/tellomi/captcha/altcha/challenge")
        .request()
        .get()) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
    verify(altchaCaptchaClient, never()).issueChallenge(any(), any(), any());
  }

  @Test
  void event() {
    // sendBeacon：POST、没有请求体；未知取值不报错，指标里记成 other
    for (final String[] query : new String[][]{
        {"e", "switch", "mode", "turnstile", "to", "altcha", "reason", "timeout", "action", "registration"},
        {"e", "solved", "mode", "altcha", "ms", "1234", "action", "challenge"},
        {"e", "whatever", "mode", "<script>", "reason", "x"}}) {

      WebTarget target = resources.getJerseyTest().target("/v1/tellomi/captcha/event");
      for (int i = 0; i < query.length; i += 2) {
        target = target.queryParam(query[i], query[i + 1]);
      }
      try (final Response response = target.request().post(Entity.text(""))) {
        assertThat(response.getStatus()).isEqualTo(204);
      }
    }
  }
}
