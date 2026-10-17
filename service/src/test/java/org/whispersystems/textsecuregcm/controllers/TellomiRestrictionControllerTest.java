/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions.Level;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions.Restriction;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/// Tellomi（ADR-0078 §3.4）：GET /v1/tellomi/restriction 只说自己的处置；没有就 204；要登录。
@ExtendWith(DropwizardExtensionsSupport.class)
class TellomiRestrictionControllerTest {

  private static final Instant UNTIL = Instant.parse("2026-10-24T10:00:00Z");
  private static final TellomiAccountRestrictions RESTRICTIONS = mock(TellomiAccountRestrictions.class);

  private static final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new TellomiRestrictionController(RESTRICTIONS))
      .build();

  @BeforeEach
  void setUp() {
    when(RESTRICTIONS.get(any())).thenReturn(Optional.empty());
  }

  private Response get() {
    return resources.getJerseyTest()
        .target("/v1/tellomi/restriction")
        .request()
        .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD))
        .get();
  }

  @Test
  void activeRestrictionIsReturnedWithTheSameBodyAsTheForbiddenSend() {
    when(RESTRICTIONS.get(AuthHelper.VALID_UUID))
        .thenReturn(Optional.of(new Restriction(Level.STRANGER, UNTIL, "20261017-abcd1234")));
    try (final Response response = get()) {
      assertEquals(200, response.getStatus());
      assertEquals("no-store", response.getHeaderString("Cache-Control"));
      final JsonNode body = response.readEntity(JsonNode.class).get("tellomiRestriction");
      assertEquals("stranger", body.get("level").asText());
      assertEquals(UNTIL.getEpochSecond(), body.get("until").asLong());
      assertEquals("abuse@tellomi.app", body.get("appeal").asText());
      assertEquals("20261017-abcd1234", body.get("case").asText());
      final Set<String> keys = new java.util.HashSet<>();
      body.fieldNames().forEachRemaining(keys::add);
      assertEquals(Set.of("level", "until", "appeal", "case"), keys);
    }
  }

  @Test
  void noRestrictionIsNoContent() {
    try (final Response response = get()) {
      assertEquals(204, response.getStatus());
    }
  }

  @Test
  void someoneElsesRestrictionIsNeverReturned() {
    when(RESTRICTIONS.get(AuthHelper.VALID_UUID_TWO)).thenReturn(Optional.of(new Restriction(Level.ALL, UNTIL)));
    try (final Response response = get()) {
      assertEquals(204, response.getStatus());
    }
  }

  @Test
  void requiresAuthentication() {
    try (final Response response = resources.getJerseyTest().target("/v1/tellomi/restriction").request().get()) {
      assertEquals(401, response.getStatus());
    }
  }

  @Test
  void serverWithoutTheListAlwaysSaysNoContent() {
    try (final Response response = new TellomiRestrictionController(null)
        .get(new AuthenticatedDevice(AuthHelper.VALID_UUID, (byte) 1, Instant.EPOCH))) {
      assertEquals(204, response.getStatus());
    }
  }
}
