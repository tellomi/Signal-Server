/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import io.dropwizard.auth.PolymorphicAuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.entities.ReserveUsernameHashRequest;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.username.TellomiReleaseProbe;
import org.whispersystems.textsecuregcm.username.UsernameHashDenylist;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.UsernameHashZkProofVerifier;

/// Tellomi（ADR-0066 §6.1，owner 2026-10-18 只放宽探针账号）：发版探针账号保留用户名用 tellomiUsernameProbe，
/// 不占 usernameReserve；别的账号照上游用 usernameReserve。
@ExtendWith(DropwizardExtensionsSupport.class)
class AccountControllerTellomiReleaseProbeTest {

  private static final AccountsManager accountsManager = mock(AccountsManager.class);
  private static final RateLimiters rateLimiters = mock(RateLimiters.class);
  private static final RateLimiter probeLimiter = mock(RateLimiter.class);
  private static final RateLimiter usernameReserveLimiter = mock(RateLimiter.class);

  /// 探针账号 = AuthHelper 的第一个账号；第二个账号是普通账号。
  private static final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new PolymorphicAuthValueFactoryProvider.Binder<>(Set.of(AuthenticatedDevice.class)))
      .addProvider(new RateLimitExceededExceptionMapper())
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new AccountController(accountsManager, rateLimiters, mock(PhoneNumberRecoveryPasswordsManager.class),
          mock(UsernameHashZkProofVerifier.class), UsernameHashDenylist.empty(),
          new TellomiReleaseProbe(Set.of(AuthHelper.VALID_UUID))))
      .build();

  private static final byte[] HASH = new byte[AccountController.USERNAME_HASH_LENGTH];

  @BeforeEach
  void setUp() throws Exception {
    reset(accountsManager, rateLimiters, probeLimiter, usernameReserveLimiter);
    when(rateLimiters.forDescriptor(RateLimiters.For.TELLOMI_USERNAME_PROBE)).thenReturn(probeLimiter);
    when(rateLimiters.getUsernameReserveLimiter()).thenReturn(usernameReserveLimiter);
    when(accountsManager.reserveUsernameHash(any(), any()))
        .thenReturn(new AccountsManager.UsernameReservation(null, HASH));
  }

  private Response reserve(final UUID account, final String password) {
    return resources.getJerseyTest()
        .target("/v1/accounts/username_hash/reserve")
        .request()
        .header(HttpHeaders.AUTHORIZATION, AuthHelper.getAuthHeader(account, password))
        .put(Entity.json(new ReserveUsernameHashRequest(List.of(HASH))));
  }

  @Test
  void theProbeAccountReservesUnderItsOwnLimit() throws Exception {
    try (final Response response = reserve(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD)) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verify(probeLimiter).validate(AuthHelper.VALID_UUID);
    verifyNoInteractions(usernameReserveLimiter);
  }

  @Test
  void anOrdinaryAccountReservesUnderTheUpstreamLimit() throws Exception {
    try (final Response response = reserve(AuthHelper.VALID_UUID_TWO, AuthHelper.VALID_PASSWORD_TWO)) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verify(usernameReserveLimiter).validate(AuthHelper.VALID_UUID_TWO);
    verifyNoInteractions(probeLimiter);
  }

  /// 没配探针账号（本地栈、测试、旧配置）：5 个参数的构造等于 NONE，人人照上游。
  @Test
  void withoutProbeAccountsNobodyIsAProbe() {
    assertThat(TellomiReleaseProbe.NONE.isProbe(AuthHelper.VALID_UUID)).isFalse();
    assertThat(TellomiReleaseProbe.NONE.size()).isZero();
  }
}
