/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.util.Base64;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.username.TellomiReleaseProbe;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/// Tellomi（ADR-0066 §6.1）：GET /v1/tellomi/username-probe/{hash} 只给发版探针账号用，按账号计 tellomiUsernameProbe 限流，
/// 只回答「占没占」；别的账号 403 且不碰限流，坏 hash 422，限流 429。
@ExtendWith(DropwizardExtensionsSupport.class)
class TellomiUsernameProbeControllerTest {

  private static final AccountsManager accountsManager = mock(AccountsManager.class);
  private static final RateLimiters rateLimiters = mock(RateLimiters.class);
  private static final RateLimiter probeLimiter = mock(RateLimiter.class);

  /// 探针账号 = AuthHelper 的第一个账号；第二个账号是普通账号。
  private static final TellomiReleaseProbe PROBE = new TellomiReleaseProbe(Set.of(AuthHelper.VALID_UUID));

  private static final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .addProvider(new RateLimitExceededExceptionMapper())
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new TellomiUsernameProbeController(accountsManager, rateLimiters, PROBE))
      .build();

  private static final byte[] HASH = new byte[AccountController.USERNAME_HASH_LENGTH];

  static {
    for (int i = 0; i < HASH.length; i++) {
      HASH[i] = (byte) (i * 7 + 3);
    }
  }

  @BeforeEach
  void setUp() {
    reset(accountsManager, rateLimiters, probeLimiter);
    when(rateLimiters.forDescriptor(RateLimiters.For.TELLOMI_USERNAME_PROBE)).thenReturn(probeLimiter);
  }

  private static String encoded(final byte[] hash) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
  }

  private Response probe(final String usernameHash, final UUID account, final String password) {
    return resources.getJerseyTest()
        .target("/v1/tellomi/username-probe/" + usernameHash)
        .request()
        .header(HttpHeaders.AUTHORIZATION, AuthHelper.getAuthHeader(account, password))
        .get();
  }

  private Response probeAsProbe(final String usernameHash) {
    return probe(usernameHash, AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD);
  }

  @Test
  void aFreeNameIsNotTaken() throws Exception {
    when(accountsManager.getByUsernameHash(any())).thenReturn(CompletableFuture.completedFuture(Optional.empty()));
    try (final Response response = probeAsProbe(encoded(HASH))) {
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.readEntity(JsonNode.class).get("taken").asBoolean()).isFalse();
    }
    verify(probeLimiter).validate(AuthHelper.VALID_UUID);
  }

  /// 只回答占没占，不回是谁占的。
  @Test
  void aTakenNameIsTakenAndNothingElseIsSaid() throws Exception {
    when(accountsManager.getByUsernameHash(any()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(mock(Account.class))));
    try (final Response response = probeAsProbe(encoded(HASH))) {
      assertThat(response.getStatus()).isEqualTo(200);
      final JsonNode body = response.readEntity(JsonNode.class);
      assertThat(body.get("taken").asBoolean()).isTrue();
      final Set<String> keys = new java.util.HashSet<>();
      body.fieldNames().forEachRemaining(keys::add);
      assertThat(keys).containsExactly("taken");
    }
  }

  /// 普通账号：403，而且不碰限流、不查库（不让普通账号借这个接口绕开按 IP 的查名限流）。
  @Test
  void anOrdinaryAccountIsForbiddenAndCostsNothing() {
    try (final Response response = probe(encoded(HASH), AuthHelper.VALID_UUID_TWO, AuthHelper.VALID_PASSWORD_TWO)) {
      assertThat(response.getStatus()).isEqualTo(403);
    }
    verifyNoInteractions(probeLimiter);
    verify(accountsManager, never()).getByUsernameHash(any());
  }

  @Test
  void notLoggedInIsUnauthorized() {
    try (final Response response = resources.getJerseyTest()
        .target("/v1/tellomi/username-probe/" + encoded(HASH))
        .request()
        .get()) {
      assertThat(response.getStatus()).isEqualTo(401);
    }
  }

  @Test
  void aBadHashIsUnprocessable() {
    try (final Response response = probeAsProbe("not*base64")) {
      assertThat(response.getStatus()).isEqualTo(422);
    }
    try (final Response response = probeAsProbe(encoded(new byte[16]))) {
      assertThat(response.getStatus()).isEqualTo(422);
    }
    verify(accountsManager, never()).getByUsernameHash(any());
  }

  @Test
  void overTheLimitIsTooManyRequests() throws Exception {
    doThrow(new RateLimitExceededException(Duration.ofSeconds(30))).when(probeLimiter).validate(AuthHelper.VALID_UUID);
    try (final Response response = probeAsProbe(encoded(HASH))) {
      assertThat(response.getStatus()).isEqualTo(429);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("30");
    }
    verify(accountsManager, never()).getByUsernameHash(any());
  }
}
