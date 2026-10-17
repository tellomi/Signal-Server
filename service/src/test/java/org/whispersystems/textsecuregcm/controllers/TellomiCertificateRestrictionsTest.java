/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.signal.libsignal.zkgroup.GenericServerSecretParams;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.CertificateGenerator;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions.Level;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions.Restriction;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/// Tellomi（ADR-0078 §3.3）：「限制全部发送」「暂停」的账号拿不到发送者证书；「限制陌生人消息」照常拿。
@ExtendWith(DropwizardExtensionsSupport.class)
class TellomiCertificateRestrictionsTest {

  private static final Instant UNTIL = Instant.parse("2026-11-16T10:00:00Z");

  private static final CertificateGenerator CERTIFICATE_GENERATOR = mock(CertificateGenerator.class);
  private static final TellomiAccountRestrictions RESTRICTIONS = mock(TellomiAccountRestrictions.class);

  private static final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new CertificateController(AuthHelper.ACCOUNTS_MANAGER, CERTIFICATE_GENERATOR,
          new ServerZkAuthOperations(ServerSecretParams.generate()), GenericServerSecretParams.generate(),
          GenericServerSecretParams.generate(), Clock.systemUTC())
          .withTellomiRestrictions(RESTRICTIONS))
      .build();

  @BeforeEach
  void setUp() {
    when(CERTIFICATE_GENERATOR.createFor(any(), anyByte(), anyBoolean())).thenReturn(new byte[]{1, 2, 3});
    when(RESTRICTIONS.get(any())).thenReturn(Optional.empty());
  }

  private Response request() {
    return resources.getJerseyTest()
        .target("/v1/certificate/delivery")
        .request()
        .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD))
        .get();
  }

  @ParameterizedTest
  @EnumSource(Level.class)
  void onlyTheHarderLevelsLoseTheirSenderCertificate(final Level level) {
    when(RESTRICTIONS.get(AuthHelper.VALID_UUID)).thenReturn(Optional.of(new Restriction(level, UNTIL)));

    try (final Response response = request()) {
      if (level.blocksSenderCertificates()) {
        assertEquals(403, response.getStatus());
        final JsonNode body = response.readEntity(JsonNode.class).get("tellomiRestriction");
        assertEquals(level.code(), body.get("level").asText());
        assertEquals(UNTIL.getEpochSecond(), body.get("until").asLong());
      } else {
        assertEquals(200, response.getStatus());
      }
    }
  }

  @Test
  void unrestrictedAccountsGetACertificate() {
    try (final Response response = request()) {
      assertEquals(200, response.getStatus());
    }
  }
}
