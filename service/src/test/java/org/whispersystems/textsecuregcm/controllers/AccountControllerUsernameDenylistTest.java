/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.dropwizard.auth.PolymorphicAuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.signal.libsignal.usernames.Username;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.entities.ReserveUsernameHashRequest;
import org.whispersystems.textsecuregcm.entities.ReserveUsernameHashResponse;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.username.UsernameHashDenylist;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.UsernameHashZkProofVerifier;

/**
 * Tellomi: the reservation endpoint must drop denied candidates before offering them, and must be indistinguishable
 * from "all taken" when nothing is left — otherwise the endpoint becomes a way to read the lexicon back out of the
 * server one guess at a time (ADR-0062 §12).
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class AccountControllerUsernameDenylistTest {

  /** Same fixture as {@link org.whispersystems.textsecuregcm.username.UsernameHashDenylistTest}: term "parityreserved". */
  private static final String FIXTURE = "/username/parity-denylist.bin";

  private static final AccountsManager accountsManager = mock(AccountsManager.class);
  private static final RateLimiters rateLimiters = mock(RateLimiters.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
  private static final PhoneNumberRecoveryPasswordsManager recoveryPasswords =
      mock(PhoneNumberRecoveryPasswordsManager.class);
  private static final UsernameHashZkProofVerifier zkProofVerifier = mock(UsernameHashZkProofVerifier.class);

  private static final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new PolymorphicAuthValueFactoryProvider.Binder<>(Set.of(AuthenticatedDevice.class)))
      .addProvider(new RateLimitExceededExceptionMapper())
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new AccountController(accountsManager, rateLimiters, recoveryPasswords, zkProofVerifier,
          loadFixture()))
      .build();

  private static UsernameHashDenylist loadFixture() {
    try (var stream = AccountControllerUsernameDenylistTest.class.getResourceAsStream(FIXTURE)) {
      final Path tmp = Files.createTempFile("denylist", ".bin");
      Files.write(tmp, stream.readAllBytes());
      return UsernameHashDenylist.load(tmp);
    } catch (final Exception e) {
      throw new AssertionError("the parity fixture must be readable", e);
    }
  }

  private static byte[] hashOf(final String username) throws Exception {
    return new Username(username).getHash();
  }

  @BeforeEach
  void setUp() {
    org.mockito.Mockito.reset(accountsManager);
  }

  @Test
  void aDeniedCandidateIsNeverOffered() throws Exception {
    final byte[] denied = hashOf("parityreserved.01");
    final byte[] allowed = hashOf("xiaoming.42");

    when(accountsManager.reserveUsernameHash(any(), any()))
        .thenReturn(new AccountsManager.UsernameReservation(null, allowed));

    try (final Response response = resources.getJerseyTest()
        .target("/v1/accounts/username_hash/reserve")
        .request()
        .header(HttpHeaders.AUTHORIZATION, AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD))
        .put(Entity.json(new ReserveUsernameHashRequest(List.of(denied, allowed))))) {

      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.readEntity(ReserveUsernameHashResponse.class).usernameHash()).isEqualTo(allowed);
    }

    @SuppressWarnings("unchecked")
    final ArgumentCaptor<List<byte[]>> offered = ArgumentCaptor.forClass(List.class);
    verify(accountsManager).reserveUsernameHash(any(), offered.capture());
    assertThat(offered.getValue()).containsExactly(allowed);
  }

  /**
   * The important half of the design: a client must not be able to tell "reserved by policy" from "somebody already
   * has it". Rather than asserting a particular body, this compares the two paths against each other — if either one
   * ever grows a distinguishing detail, the test fails.
   */
  @Test
  void anAllDeniedRequestLooksExactlyLikeAllTaken() throws Exception {
    final int deniedStatus;
    final String deniedBody;
    try (final Response response = reserve(hashOf("parityreserved.01"), hashOf("parityreserved.02"))) {
      deniedStatus = response.getStatus();
      deniedBody = response.readEntity(String.class);
    }

    // …and the storage layer was never consulted, so a denied name cannot slip through on a race either.
    verify(accountsManager, never()).reserveUsernameHash(any(), any());

    when(accountsManager.reserveUsernameHash(any(), any()))
        .thenThrow(new org.whispersystems.textsecuregcm.storage.UsernameHashNotAvailableException());

    final int takenStatus;
    final String takenBody;
    try (final Response response = reserve(hashOf("alice.10"), hashOf("alice.11"))) {
      takenStatus = response.getStatus();
      takenBody = response.readEntity(String.class);
    }

    assertThat(deniedStatus).isEqualTo(409).isEqualTo(takenStatus);
    assertThat(deniedBody).isEqualTo(takenBody);
  }

  private Response reserve(final byte[]... hashes) {
    return resources.getJerseyTest()
        .target("/v1/accounts/username_hash/reserve")
        .request()
        .header(HttpHeaders.AUTHORIZATION, AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD))
        .put(Entity.json(new ReserveUsernameHashRequest(List.of(hashes))));
  }

  @Test
  void ordinaryReservationsAreUntouched() throws Exception {
    final byte[] first = hashOf("alice.10");
    final byte[] second = hashOf("alice.11");

    when(accountsManager.reserveUsernameHash(any(), any()))
        .thenReturn(new AccountsManager.UsernameReservation(null, first));

    try (final Response response = resources.getJerseyTest()
        .target("/v1/accounts/username_hash/reserve")
        .request()
        .header(HttpHeaders.AUTHORIZATION, AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD))
        .put(Entity.json(new ReserveUsernameHashRequest(List.of(first, second))))) {

      assertThat(response.getStatus()).isEqualTo(200);
    }

    @SuppressWarnings("unchecked")
    final ArgumentCaptor<List<byte[]>> offered = ArgumentCaptor.forClass(List.class);
    verify(accountsManager).reserveUsernameHash(any(), offered.capture());
    assertThat(offered.getValue()).containsExactly(first, second);
  }
}
