/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.dropwizard.auth.basic.BasicCredentials;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions;
import org.whispersystems.textsecuregcm.util.TestClock;

/// Tellomi（ADR-0078 §3.3）：暂停的账号凭证对了也鉴权失败；密码错了照旧是密码错（不探出谁被暂停）；没暂停照常。
class TellomiSuspendedAuthenticationTest {

  private static final String PASSWORD = "12345";

  private final UUID uuid = UUID.randomUUID();
  private TellomiAccountRestrictions restrictions;
  private SaltedTokenHash credentials;
  private AccountAuthenticator authenticator;

  @BeforeEach
  void setUp() {
    final AccountsManager accountsManager = mock(AccountsManager.class);
    final Account account = mock(Account.class);
    final Device device = mock(Device.class);
    credentials = mock(SaltedTokenHash.class);
    restrictions = mock(TellomiAccountRestrictions.class);

    when(accountsManager.getByAccountIdentifier(uuid)).thenReturn(Optional.of(account));
    when(account.getAccountIdentifier()).thenReturn(uuid);
    when(account.getDevice((byte) 1)).thenReturn(Optional.of(device));
    when(account.getPrimaryDevice()).thenReturn(device);
    when(device.getId()).thenReturn((byte) 1);
    when(device.getAuthTokenHash()).thenReturn(credentials);
    when(credentials.verify(PASSWORD)).thenReturn(true);
    when(accountsManager.updateDeviceLastSeen(any(), any(), anyLong())).thenReturn(account);

    authenticator = new AccountAuthenticator(accountsManager, TestClock.now()).withTellomiRestrictions(restrictions);
  }

  @Test
  void suspendedAccountsCannotAuthenticate() {
    when(restrictions.isSuspended(uuid)).thenReturn(true);
    assertThat(authenticator.authenticate(new BasicCredentials(uuid.toString(), PASSWORD))).isEmpty();
  }

  @Test
  void aWrongPasswordNeverLooksAtTheRestrictions() {
    when(restrictions.isSuspended(uuid)).thenReturn(true);
    assertThat(authenticator.authenticate(new BasicCredentials(uuid.toString(), "wrong"))).isEmpty();
    verify(restrictions, never()).isSuspended(any());
  }

  @Test
  void everyoneElseAuthenticatesAsBefore() {
    when(restrictions.isSuspended(uuid)).thenReturn(false);
    assertThat(authenticator.authenticate(new BasicCredentials(uuid.toString(), PASSWORD))).isPresent();
  }
}
