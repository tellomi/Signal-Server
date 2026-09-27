/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import org.whispersystems.textsecuregcm.util.TestClock;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anySet;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.whispersystems.textsecuregcm.auth.DisconnectionRequestManager;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClient;
import org.whispersystems.textsecuregcm.redis.RedisClusterExtension;
import org.whispersystems.textsecuregcm.securestorage.SecureStorageClient;
import org.whispersystems.textsecuregcm.securevaluerecovery.SecureValueRecoveryClient;
import org.whispersystems.textsecuregcm.storage.DynamoDbExtensionSchema.Tables;
import org.whispersystems.textsecuregcm.tests.util.AccountsHelper;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import org.whispersystems.textsecuregcm.util.TestRandomUtil;
import org.whispersystems.textsecuregcm.util.ThrowingSupplier;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.UpdateItemRequest;

class AccountsManagerUsernameIntegrationTest {

  // Tellomi: one clock for Accounts and AccountsManager, so the rename cooldown (ADR-0066) can be moved past.
  // Unpinned it follows real time, so upstream's tests see no difference.
  private final TestClock clock = TestClock.now();

  private static final String BASE_64_URL_USERNAME_HASH_1 = "9p6Tip7BFefFOJzv4kv4GyXEYsBVfk_WbjNejdlOvQE";
  private static final String BASE_64_URL_USERNAME_HASH_2 = "NLUom-CHwtemcdvOTTXdmXmzRIV7F05leS8lwkVK_vc";
  private static final String BASE_64_URL_ENCRYPTED_USERNAME_1 = "md1votbj9r794DsqTNrBqA";
  private static final String BASE_64_URL_ENCRYPTED_USERNAME_2 = "9hrqVLy59bzgPse-S9NUsA";
  private static final byte[] USERNAME_HASH_1 = Base64.getUrlDecoder().decode(BASE_64_URL_USERNAME_HASH_1);
  private static final byte[] USERNAME_HASH_2 = Base64.getUrlDecoder().decode(BASE_64_URL_USERNAME_HASH_2);
  private static final byte[] ENCRYPTED_USERNAME_1 = Base64.getUrlDecoder().decode(BASE_64_URL_ENCRYPTED_USERNAME_1);
  private static final byte[] ENCRYPTED_USERNAME_2 = Base64.getUrlDecoder().decode(BASE_64_URL_ENCRYPTED_USERNAME_2);

  @RegisterExtension
  static final DynamoDbExtension DYNAMO_DB_EXTENSION = new DynamoDbExtension(
      Tables.ACCOUNTS,
      Tables.NUMBERS,
      Tables.USERNAMES,
      Tables.DELETED_ACCOUNTS,
      Tables.PNI,
      Tables.PNI_ASSIGNMENTS,
      Tables.EC_KEYS,
      Tables.PAGED_PQ_KEYS,
      Tables.REPEATED_USE_EC_SIGNED_PRE_KEYS,
      Tables.REPEATED_USE_KEM_SIGNED_PRE_KEYS,
      Tables.REDEEMED_RECEIPTS,
      Tables.PHONE_NUMBER_RECOVERY_PASSWORDS);

  @RegisterExtension
  static RedisClusterExtension CACHE_CLUSTER_EXTENSION = RedisClusterExtension.builder().build();

  @RegisterExtension
  static final S3LocalStackExtension S3_EXTENSION = new S3LocalStackExtension("testbucket");

  private AccountsManager accountsManager;
  private Accounts accounts;

  @BeforeEach
  void setup() throws Exception {
    final DynamoDbAsyncClient dynamoDbAsyncClient = DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient();
    final KeysManager keysManager = new KeysManager(
        new SingleUseECPreKeyStore(dynamoDbAsyncClient, DynamoDbExtensionSchema.Tables.EC_KEYS.tableName()),
        new PagedSingleUseKEMPreKeyStore(dynamoDbAsyncClient,
            S3_EXTENSION.getS3Client(),
            DynamoDbExtensionSchema.Tables.PAGED_PQ_KEYS.tableName(),
            S3_EXTENSION.getBucketName()),
        new RepeatedUseECSignedPreKeyStore(dynamoDbAsyncClient,
            DynamoDbExtensionSchema.Tables.REPEATED_USE_EC_SIGNED_PRE_KEYS.tableName()),
        new RepeatedUseKEMSignedPreKeyStore(dynamoDbAsyncClient,
            DynamoDbExtensionSchema.Tables.REPEATED_USE_KEM_SIGNED_PRE_KEYS.tableName()));

    accounts = Mockito.spy(new Accounts(
        clock,
        DYNAMO_DB_EXTENSION.getDynamoDbClient(),
        DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient(),
        new RedeemedReceiptsManager(Clock.systemUTC(), Tables.REDEEMED_RECEIPTS.tableName(),
            DYNAMO_DB_EXTENSION.getDynamoDbClient()),
        Tables.ACCOUNTS.tableName(),
        Tables.NUMBERS.tableName(),
        Tables.PNI_ASSIGNMENTS.tableName(),
        Tables.USERNAMES.tableName(),
        Tables.DELETED_ACCOUNTS.tableName(),
        Tables.USED_LINK_DEVICE_TOKENS.tableName()));

    final AccountLockManager accountLockManager = mock(AccountLockManager.class);

    doAnswer(invocation -> {
      final ThrowingSupplier<?, ?> task = invocation.getArgument(1);
      return task.get();
    }).when(accountLockManager).withLock(anySet(), any());

    // Tellomi (#1156): the deletion tests below go through AccountsManager#delete, which takes the single-account lock
    // and clears secure storage and SVR.
    doAnswer(invocation -> {
      final ThrowingSupplier<?, ?> task = invocation.getArgument(1);
      return task.get();
    }).when(accountLockManager).withSingleAccountLock(any(), any());

    final SecureStorageClient secureStorageClient = mock(SecureStorageClient.class);
    when(secureStorageClient.deleteStoredData(any())).thenReturn(CompletableFuture.completedFuture(null));

    final SecureValueRecoveryClient svr2Client = mock(SecureValueRecoveryClient.class);
    when(svr2Client.removeData(any(UUID.class))).thenReturn(CompletableFuture.completedFuture(null));

    final PhoneNumberIdentifiers phoneNumberIdentifiers =
        new PhoneNumberIdentifiers(DYNAMO_DB_EXTENSION.getDynamoDbAsyncClient(), Tables.PNI.tableName());

    final MessagesManager messageManager = mock(MessagesManager.class);
    final ProfilesManager profileManager = mock(ProfilesManager.class);
    when(messageManager.clear(any())).thenReturn(CompletableFuture.completedFuture(null));
    when(profileManager.deleteAll(any(), anyBoolean())).thenReturn(CompletableFuture.completedFuture(null));

    final DisconnectionRequestManager disconnectionRequestManager = mock(DisconnectionRequestManager.class);
    when(disconnectionRequestManager.requestDisconnection(any())).thenReturn(CompletableFuture.completedFuture(null));

    final PhoneNumberRecoveryPasswordsManager phoneNumberRecoveryPasswordsManager =
        new PhoneNumberRecoveryPasswordsManager(new PhoneNumberRecoveryPasswords(
            Tables.PHONE_NUMBER_RECOVERY_PASSWORDS.tableName(),
            Duration.ofDays(1),
            DYNAMO_DB_EXTENSION.getDynamoDbClient(),
            Clock.systemUTC()));

    accountsManager = new AccountsManager(
        accounts,
        phoneNumberIdentifiers,
        CACHE_CLUSTER_EXTENSION.getRedisCluster(),
        mock(FaultTolerantRedisClient.class),
        accountLockManager,
        keysManager,
        messageManager,
        profileManager,
        mock(ChangeNumberWaitingPeriodManager.class),
        secureStorageClient,
        svr2Client,
        disconnectionRequestManager,
        phoneNumberRecoveryPasswordsManager,
        Executors.newSingleThreadScheduledExecutor(),
        Executors.newSingleThreadScheduledExecutor(),
        clock,
        "link-device-secret".getBytes(StandardCharsets.UTF_8),
        AccountsManager.TOTP.getTimeStep().dividedBy(2),
        null);
  }

  @Test
  void testNoUsernames() {
    final Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");

    List<byte[]> usernameHashes = List.of(USERNAME_HASH_1, USERNAME_HASH_2);
    int i = 0;
    for (byte[] hash : usernameHashes) {
      final Map<String, AttributeValue> item = new HashMap<>(Map.of(
          Accounts.UsernameTable.ATTR_ACCOUNT_UUID, AttributeValues.fromUUID(UUID.randomUUID()),
          Accounts.UsernameTable.KEY_USERNAME_HASH, AttributeValues.fromByteArray(hash)));
      // half of these are taken usernames, half are only reservations (have a TTL)
      if (i % 2 == 0) {
        item.put(Accounts.UsernameTable.ATTR_TTL,
            AttributeValues.fromLong(Instant.now().plus(Duration.ofMinutes(1)).getEpochSecond()));
      }
      i++;
      DYNAMO_DB_EXTENSION.getDynamoDbClient().putItem(PutItemRequest.builder()
          .tableName(Tables.USERNAMES.tableName())
          .item(item)
          .build());
    }

    assertThrows(UsernameHashNotAvailableException.class,
        () -> accountsManager.reserveUsernameHash(account.getAccountIdentifier(), usernameHashes));

    assertThat(accountsManager.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow().getUsernameHash()).isEmpty();
  }

  @Test
  void testReserveUsernameGetFirstAvailableChoice() throws UsernameHashNotAvailableException {
    final Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");

    ArrayList<byte[]> usernameHashes = new ArrayList<>(Arrays.asList(USERNAME_HASH_1, USERNAME_HASH_2));
    for (byte[] hash : usernameHashes) {
      DYNAMO_DB_EXTENSION.getDynamoDbClient().putItem(PutItemRequest.builder()
          .tableName(Tables.USERNAMES.tableName())
          .item(Map.of(
              Accounts.UsernameTable.ATTR_ACCOUNT_UUID, AttributeValues.fromUUID(UUID.randomUUID()),
              Accounts.UsernameTable.KEY_USERNAME_HASH, AttributeValues.fromByteArray(hash)))
          .build());
    }


    byte[] availableHash = TestRandomUtil.nextBytes(32);
    usernameHashes.add(availableHash);
    usernameHashes.add(TestRandomUtil.nextBytes(32));

    final byte[] username = accountsManager
        .reserveUsernameHash(account.getAccountIdentifier(), usernameHashes)
        .reservedUsernameHash();

    assertArrayEquals(username, availableHash);
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  public void testReserveConfirmClear(final boolean numberless)
      throws UsernameHashNotAvailableException, UsernameReservationNotFoundException {
    Account account = new AccountsHelper.AccountBuilder(accountsManager)
        .e164(numberless ? null : "+18005551111")
        .build();

    // reserve
    AccountsManager.UsernameReservation reservation =
        accountsManager.reserveUsernameHash(account.getAccountIdentifier(), List.of(USERNAME_HASH_1));

    assertArrayEquals(USERNAME_HASH_1, reservation.account().getReservedUsernameHash().orElseThrow());
    assertThat(accountsManager.getByUsernameHash(reservation.reservedUsernameHash()).join()).isEmpty();

    // confirm
    account = accountsManager.confirmReservedUsernameHash(
        reservation.account().getAccountIdentifier(),
        reservation.reservedUsernameHash(),
        ENCRYPTED_USERNAME_1);
    assertArrayEquals(USERNAME_HASH_1, account.getUsernameHash().orElseThrow());
    assertThat(accountsManager.getByUsernameHash(USERNAME_HASH_1).join().orElseThrow().getAccountIdentifier()).isEqualTo(
        account.getAccountIdentifier());
    assertThat(account.getUsernameLinkHandle()).isNotNull();
    assertThat(accountsManager.getByUsernameLinkHandle(account.getUsernameLinkHandle()).join().orElseThrow().getAccountIdentifier())
        .isEqualTo(account.getAccountIdentifier());

    // clear
    account = accountsManager.clearUsernameHash(account.getAccountIdentifier());
    assertThat(accountsManager.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();
    assertThat(accountsManager.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow().getUsernameHash()).isEmpty();
  }

  @Test
  public void testHold()
      throws UsernameHashNotAvailableException, UsernameReservationNotFoundException {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");

    AccountsManager.UsernameReservation reservation =
        accountsManager.reserveUsernameHash(account.getAccountIdentifier(), List.of(USERNAME_HASH_1));

    // confirm
    account = accountsManager.confirmReservedUsernameHash(
        reservation.account().getAccountIdentifier(),
        reservation.reservedUsernameHash(),
        ENCRYPTED_USERNAME_1);

    // clear
    account = accountsManager.clearUsernameHash(account.getAccountIdentifier());
    assertThat(accountsManager.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();
    assertThat(accountsManager.getByAccountIdentifier(account.getAccountIdentifier()).orElseThrow().getUsernameHash()).isEmpty();

    assertThat(accountsManager.getByUsernameHash(reservation.reservedUsernameHash()).join()).isEmpty();

    Account account2 = AccountsHelper.createAccount(accountsManager, "+18005552222");
    assertThrows(UsernameHashNotAvailableException.class,
        () -> accountsManager.reserveUsernameHash(account2.getAccountIdentifier(), List.of(USERNAME_HASH_1)),
        "account2 should not be able to reserve a held hash");
  }

  @Test
  public void testReservationLapsed()
      throws UsernameHashNotAvailableException, UsernameReservationNotFoundException {
    final Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");

    AccountsManager.UsernameReservation reservation1 =
        accountsManager.reserveUsernameHash(account.getAccountIdentifier(), List.of(USERNAME_HASH_1));

    long past = Instant.now().minus(Duration.ofMinutes(1)).getEpochSecond();
    // force expiration
    DYNAMO_DB_EXTENSION.getDynamoDbClient().updateItem(UpdateItemRequest.builder()
        .tableName(Tables.USERNAMES.tableName())
        .key(Map.of(Accounts.UsernameTable.KEY_USERNAME_HASH, AttributeValues.fromByteArray(USERNAME_HASH_1)))
        .updateExpression("SET #ttl = :ttl")
        .expressionAttributeNames(Map.of("#ttl", Accounts.UsernameTable.ATTR_TTL))
        .expressionAttributeValues(Map.of(":ttl", AttributeValues.fromLong(past)))
        .build());

    // a different account should be able to reserve it
    Account account2 = AccountsHelper.createAccount(accountsManager, "+18005552222");

    final AccountsManager.UsernameReservation reservation2 =
        accountsManager.reserveUsernameHash(account2.getAccountIdentifier(), List.of(USERNAME_HASH_1));
    assertArrayEquals(USERNAME_HASH_1, reservation2.reservedUsernameHash());

    assertThrows(UsernameHashNotAvailableException.class,
        () -> accountsManager.confirmReservedUsernameHash(reservation1.account().getAccountIdentifier(), USERNAME_HASH_1, ENCRYPTED_USERNAME_1));
    account2 = accountsManager.confirmReservedUsernameHash(reservation2.account().getAccountIdentifier(), USERNAME_HASH_1, ENCRYPTED_USERNAME_1);
    assertEquals(accountsManager.getByUsernameHash(USERNAME_HASH_1).join().orElseThrow().getAccountIdentifier(), account2.getAccountIdentifier());
    assertArrayEquals(USERNAME_HASH_1, account2.getUsernameHash().orElseThrow());
  }

  @Test
  void testUsernameSetReserveAnotherClearSetReserved()
      throws UsernameHashNotAvailableException, UsernameReservationNotFoundException {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");

    // Set username hash
    final AccountsManager.UsernameReservation reservation1 =
        accountsManager.reserveUsernameHash(account.getAccountIdentifier(), List.of(USERNAME_HASH_1));

    account = accountsManager.confirmReservedUsernameHash(reservation1.account().getAccountIdentifier(), USERNAME_HASH_1, ENCRYPTED_USERNAME_1);

    // Reserve another hash on the same account
    final AccountsManager.UsernameReservation reservation2 =
        accountsManager.reserveUsernameHash(account.getAccountIdentifier(), List.of(USERNAME_HASH_2));

    account = reservation2.account();

    assertArrayEquals(USERNAME_HASH_2, account.getReservedUsernameHash().orElseThrow());
    assertArrayEquals(USERNAME_HASH_1, account.getUsernameHash().orElseThrow());
    assertArrayEquals(ENCRYPTED_USERNAME_1, account.getEncryptedUsername().orElseThrow());

    // Clear the set username hash but not the reserved one
    account = accountsManager.clearUsernameHash(account.getAccountIdentifier());
    assertThat(account.getReservedUsernameHash()).isPresent();
    assertThat(account.getUsernameHash()).isEmpty();

    // Confirm second reservation
    account = accountsManager.confirmReservedUsernameHash(account.getAccountIdentifier(), reservation2.reservedUsernameHash(), ENCRYPTED_USERNAME_2);
    assertArrayEquals(USERNAME_HASH_2, account.getUsernameHash().orElseThrow());
    assertArrayEquals(ENCRYPTED_USERNAME_2, account.getEncryptedUsername().orElseThrow());
  }

  @Test
  public void testReclaim()
      throws UsernameHashNotAvailableException, UsernameReservationNotFoundException {
    final Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
    final AccountsManager.UsernameReservation reservation1 =
        accountsManager.reserveUsernameHash(account.getAccountIdentifier(), List.of(USERNAME_HASH_1));
    accountsManager.confirmReservedUsernameHash(reservation1.account().getAccountIdentifier(), USERNAME_HASH_1, ENCRYPTED_USERNAME_1);

    // "reclaim" the account by re-registering
    Account reclaimed = AccountsHelper.createAccount(accountsManager, "+18005551111");

    // the username should still be reserved, but no longer on our account.
    assertThat(reclaimed.getUsernameHash()).isEmpty();

    // Make sure we can't lookup the account
    assertThat(accountsManager.getByUsernameHash(USERNAME_HASH_1).join()).isEmpty();

    // confirm it again
    accountsManager.confirmReservedUsernameHash(reclaimed.getAccountIdentifier(), USERNAME_HASH_1, ENCRYPTED_USERNAME_1);
    assertThat(accountsManager.getByUsernameHash(USERNAME_HASH_1).join()).isPresent();
  }

  @ParameterizedTest
  @ValueSource(booleans = {false, true})
  public void testUsernameLinks(final boolean numberless)
      throws UsernameHashNotAvailableException, UsernameReservationNotFoundException {
    final UUID accountIdentifier;
    {
      final Account account = new AccountsHelper.AccountBuilder(accountsManager)
          .e164(numberless ? null : "+18005551111")
          .build();
      accountIdentifier = account.getAccountIdentifier();
    }

    final AccountsManager.UsernameReservation reservation =
        accountsManager.reserveUsernameHash(accountIdentifier, List.of(USERNAME_HASH_1));

    accountsManager.confirmReservedUsernameHash(accountIdentifier, reservation.reservedUsernameHash(), ENCRYPTED_USERNAME_1);

    final UUID linkHandle = UUID.randomUUID();
    final byte[] encryptedUsername = TestRandomUtil.nextBytes(32);
    accountsManager.update(accountIdentifier, account -> account.setUsernameLinkDetails(linkHandle, encryptedUsername));

    final Optional<Account> maybeAccount = accountsManager.getByUsernameLinkHandle(linkHandle).join();
    assertTrue(maybeAccount.isPresent());
    assertTrue(maybeAccount.get().getEncryptedUsername().isPresent());
    assertArrayEquals(encryptedUsername, maybeAccount.get().getEncryptedUsername().get());

    // making some unrelated change and updating account to check that username link data is still there
    final Optional<Account> accountToChange = accountsManager.getByAccountIdentifier(accountIdentifier);
    assertTrue(accountToChange.isPresent());
    accountsManager.update(accountToChange.get().getAccountIdentifier(), a -> a.setDiscoverableByPhoneNumber(!a.isDiscoverableByPhoneNumber()));
    final Optional<Account> accountAfterChange = accountsManager.getByUsernameLinkHandle(linkHandle).join();
    assertTrue(accountAfterChange.isPresent());
    assertTrue(accountAfterChange.get().getEncryptedUsername().isPresent());
    assertArrayEquals(encryptedUsername, accountAfterChange.get().getEncryptedUsername().get());

    // now deleting the link
    final Optional<Account> accountToDeleteLink = accountsManager.getByAccountIdentifier(accountIdentifier);
    accountsManager.update(accountToDeleteLink.orElseThrow().getAccountIdentifier(), a -> a.setUsernameLinkDetails(null, null));
    assertTrue(accounts.getByUsernameLinkHandle(linkHandle).join().isEmpty());
  }

  // ── Tellomi: rename cooldown (ADR-0066, TR-ID-01 「首次设置不计」; 180 days since owner 2026-09-27) ──

  private Account setUsername(Account account, final byte[] usernameHash) throws Exception {
    accountsManager.reserveUsernameHash(account.getAccountIdentifier(), List.of(usernameHash));
    return accountsManager.confirmReservedUsernameHash(account.getAccountIdentifier(), usernameHash, ENCRYPTED_USERNAME_1);
  }

  @Test
  void firstUsernameThenOneFreeChangeThenCooldown() throws Exception {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
    account = setUsername(account, USERNAME_HASH_1);
    assertTrue(account.getUsernameChangedAt().isEmpty(), "the first username an account sets does not start the cooldown");

    account = setUsername(account, USERNAME_HASH_2);
    assertTrue(account.getUsernameChangedAt().isPresent(), "replacing a username starts the cooldown");

    final UUID aci = account.getAccountIdentifier();
    final UsernameChangeCooldownException e = assertThrows(UsernameChangeCooldownException.class,
        () -> accountsManager.reserveUsernameHash(aci, List.of(TestRandomUtil.nextBytes(32))));
    assertTrue(e.getRetryAfter().compareTo(AccountsManager.DEFAULT_USERNAME_CHANGE_COOLDOWN.minusMinutes(1)) > 0
        && e.getRetryAfter().compareTo(AccountsManager.DEFAULT_USERNAME_CHANGE_COOLDOWN) <= 0,
        "Retry-After should be about the whole cooldown, was " + e.getRetryAfter());
  }

  @Test
  void takingBackAHeldNameIsAllowedDuringTheCooldown() throws Exception {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
    account = setUsername(account, USERNAME_HASH_1);
    account = setUsername(account, USERNAME_HASH_2);

    // USERNAME_HASH_1 is now one of this account's holds: undoing the change cannot squat anything.
    account = setUsername(account, USERNAME_HASH_1);
    assertArrayEquals(USERNAME_HASH_1, account.getUsernameHash().orElseThrow());
  }

  @Test
  void theCooldownEndsWhenItIsOver() throws Exception {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
    account = setUsername(account, USERNAME_HASH_1);
    account = setUsername(account, USERNAME_HASH_2);

    clock.pin(clock.instant().plus(AccountsManager.DEFAULT_USERNAME_CHANGE_COOLDOWN).plusSeconds(1));
    try {
      final byte[] third = TestRandomUtil.nextBytes(32);
      assertArrayEquals(third,
          accountsManager.reserveUsernameHash(account.getAccountIdentifier(), List.of(third)).reservedUsernameHash());
    } finally {
      clock.unpin();
    }
  }

  @Test
  void clearingThenSettingANewNameCountsAsAChange() throws Exception {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
    account = setUsername(account, USERNAME_HASH_1);
    account = accountsManager.clearUsernameHash(account.getAccountIdentifier());

    // Not the account's first username any more (USERNAME_HASH_1 is held), so this starts the cooldown …
    account = setUsername(account, USERNAME_HASH_2);
    assertTrue(account.getUsernameChangedAt().isPresent());

    // … and clear + set cannot be used to rename again straight away.
    final UUID aci = account.getAccountIdentifier();
    assertThrows(UsernameChangeCooldownException.class,
        () -> accountsManager.reserveUsernameHash(aci, List.of(TestRandomUtil.nextBytes(32))));
  }

  /**
   * Signal-Server#4 review: re-registering (new phone, restore) must not reset the cooldown or forget the holds —
   * otherwise every re-registration is two free renames. Reclaiming the original username afterwards still works.
   */
  @Test
  void reRegisteringKeepsTheCooldownAndTheHolds() throws Exception {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
    account = setUsername(account, USERNAME_HASH_1);
    account = setUsername(account, USERNAME_HASH_2);
    final java.time.Instant changedAt = account.getUsernameChangedAt().orElseThrow();

    final Account reclaimed = AccountsHelper.createAccount(accountsManager, "+18005551111");
    assertEquals(account.getAccountIdentifier(), reclaimed.getAccountIdentifier());
    assertEquals(java.util.Optional.of(changedAt), reclaimed.getUsernameChangedAt());
    assertTrue(reclaimed.getUsernameHolds().stream().anyMatch(h -> java.util.Arrays.equals(h.usernameHash(), USERNAME_HASH_1)));

    final UUID aci = reclaimed.getAccountIdentifier();
    assertThrows(UsernameChangeCooldownException.class,
        () -> accountsManager.reserveUsernameHash(aci, List.of(TestRandomUtil.nextBytes(32))));

    // The restore path (Android UsernameRepository.reclaimUsernameIfNecessary) confirms the original name directly.
    final Account restored = accountsManager.confirmReservedUsernameHash(aci, USERNAME_HASH_2, ENCRYPTED_USERNAME_2);
    assertArrayEquals(USERNAME_HASH_2, restored.getUsernameHash().orElseThrow());
  }

  /** ADR-0066 §6.2: taking back a held name is allowed during the cooldown, and restarts it (no flip-flopping). */
  @Test
  void takingBackAHeldNameRestartsTheCooldown() throws Exception {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
    account = setUsername(account, USERNAME_HASH_1);
    account = setUsername(account, USERNAME_HASH_2);

    final java.time.Instant tenDaysLater = clock.instant().plus(java.time.Duration.ofDays(10));
    clock.pin(tenDaysLater);
    try {
      account = setUsername(account, USERNAME_HASH_1);
      assertEquals(java.util.Optional.of(java.time.Instant.ofEpochSecond(tenDaysLater.getEpochSecond())),
          account.getUsernameChangedAt());

      final UUID aci = account.getAccountIdentifier();
      final UsernameChangeCooldownException e = assertThrows(UsernameChangeCooldownException.class,
          () -> accountsManager.reserveUsernameHash(aci, List.of(TestRandomUtil.nextBytes(32))));
      assertTrue(e.getRetryAfter().compareTo(AccountsManager.DEFAULT_USERNAME_CHANGE_COOLDOWN.minusSeconds(1)) >= 0,
          "the cooldown restarted at the take-back, so about 30 days are left: " + e.getRetryAfter());
    } finally {
      clock.unpin();
    }
  }

  // ── Tellomi (#1156): deleting an account holds its username for 30 days; only the same number gets it back ──

  /// Creates an account for `number` with USERNAME_HASH_1 and deletes it the way every deletion path does.
  private Account deleteAccountWithUsername(final String number) throws Exception {
    final Account account = setUsername(AccountsHelper.createAccount(accountsManager, number), USERNAME_HASH_1);
    accountsManager.delete(account.getAccountIdentifier(), AccountsManager.DeletionReason.USER_REQUEST);
    assertTrue(accountsManager.getByAccountIdentifier(account.getAccountIdentifier()).isEmpty());
    return account;
  }

  @Test
  void aDeletedAccountsUsernameIsHeldFromEveryoneElse() throws Exception {
    final Instant deletedAt = clock.instant();
    clock.pin(deletedAt);
    try {
      deleteAccountWithUsername("+18005551111");
      final UUID other = AccountsHelper.createAccount(accountsManager, "+18005552222").getAccountIdentifier();

      clock.pin(deletedAt.plus(Accounts.USERNAME_HOLD_DURATION).minusSeconds(1));

      // Answered exactly like a name somebody is using (REST 409 / gRPC UsernameNotAvailable) …
      assertThrows(UsernameHashNotAvailableException.class,
          () -> accountsManager.reserveUsernameHash(other, List.of(USERNAME_HASH_1)),
          "another account reserved a deleted account's username inside the 30-day hold");
      // … confirming without a reservation is refused before storage is touched (REST 409) …
      assertThrows(UsernameReservationNotFoundException.class,
          () -> accountsManager.confirmReservedUsernameHash(other, USERNAME_HASH_1, ENCRYPTED_USERNAME_1));
      // … and a lookup finds nobody (REST 404), as for every held name: nothing points at the deleted account.
      assertTrue(accountsManager.getByUsernameHash(USERNAME_HASH_1).join().isEmpty());
      assertTrue(accountsManager.getByAccountIdentifier(other).orElseThrow().getUsernameHash().isEmpty());
    } finally {
      clock.unpin();
    }
  }

  @Test
  void reRegisteringTheSameNumberWithinThirtyDaysGetsTheUsernameBack() throws Exception {
    final Instant deletedAt = clock.instant();
    clock.pin(deletedAt);
    try {
      final Account deleted = deleteAccountWithUsername("+18005551111");

      clock.pin(deletedAt.plus(Accounts.USERNAME_HOLD_DURATION).minusSeconds(1));

      final Account reRegistered = AccountsHelper.createAccount(accountsManager, "+18005551111");
      assertEquals(deleted.getAccountIdentifier(), reRegistered.getAccountIdentifier(),
          "within 30 days the same number gets its old ACI back (tellomi#1339)");
      assertTrue(reRegistered.getUsernameHash().isEmpty(), "the username itself is not restored, only reclaimable");

      final Account reclaimed = setUsername(reRegistered, USERNAME_HASH_1);
      assertArrayEquals(USERNAME_HASH_1, reclaimed.getUsernameHash().orElseThrow());
      assertEquals(Optional.of(deleted.getAccountIdentifier()),
          accountsManager.getByUsernameHash(USERNAME_HASH_1).join().map(Account::getAccountIdentifier));
    } finally {
      clock.unpin();
    }
  }

  @Test
  void afterThirtyDaysAnyoneCanTakeADeletedAccountsUsername() throws Exception {
    final Instant deletedAt = clock.instant();
    clock.pin(deletedAt);
    try {
      deleteAccountWithUsername("+18005551111");

      clock.pin(deletedAt.plus(Accounts.USERNAME_HOLD_DURATION).plusSeconds(1));

      final Account other = setUsername(AccountsHelper.createAccount(accountsManager, "+18005552222"), USERNAME_HASH_1);
      assertArrayEquals(USERNAME_HASH_1, other.getUsernameHash().orElseThrow());
      assertEquals(Optional.of(other.getAccountIdentifier()),
          accountsManager.getByUsernameHash(USERNAME_HASH_1).join().map(Account::getAccountIdentifier));
    } finally {
      clock.unpin();
    }
  }

  // ── Tellomi (tellomi/tellomi#1397, owner 2026-09-27): after deleting and re-registering the same number, the old
  //    name is never handed back but can be typed in again, and exactly one username set is free of the cooldown ──

  /// USERNAME_HASH_1, then renamed to USERNAME_HASH_2 (so inside the rename cooldown, USERNAME_HASH_1 held), then
  /// deleted. The clock must be pinned.
  private Account deleteAccountInsideTheCooldown(final String number) throws Exception {
    Account account = AccountsHelper.createAccount(accountsManager, number);
    account = setUsername(account, USERNAME_HASH_1);
    account = setUsername(account, USERNAME_HASH_2);
    assertTrue(account.getUsernameChangedAt().isPresent());
    accountsManager.delete(account.getAccountIdentifier(), AccountsManager.DeletionReason.USER_REQUEST);
    return account;
  }

  @Test
  void afterDeletionTheOldNameIsNotHandedBackButCanBeTypedAgain() throws Exception {
    clock.pin(Instant.ofEpochSecond(clock.instant().getEpochSecond()));
    try {
      final Account deleted = deleteAccountInsideTheCooldown("+18005551111");
      clock.pin(clock.instant().plus(Duration.ofDays(2)));

      final Account reRegistered = AccountsHelper.createAccount(accountsManager, "+18005551111");
      assertEquals(deleted.getAccountIdentifier(), reRegistered.getAccountIdentifier());
      assertTrue(reRegistered.getUsernameHash().isEmpty(), "the pre-deletion name must not be handed back");
      assertTrue(reRegistered.getReservedUsernameHash().isEmpty(), "the pre-deletion name must not be handed back");
      assertNull(reRegistered.getUsernameLinkHandle());

      // The user types it in: the client's reserve → confirm goes through, no 429.
      final Account reclaimed = assertDoesNotThrow(() -> setUsername(reRegistered, USERNAME_HASH_2),
          "taking back the pre-deletion name after re-registering the same number");
      assertArrayEquals(USERNAME_HASH_2, reclaimed.getUsernameHash().orElseThrow());

      // That was the one free set, so it started a full cooldown.
      final UUID aci = reclaimed.getAccountIdentifier();
      final UsernameChangeCooldownException e = assertThrows(UsernameChangeCooldownException.class,
          () -> accountsManager.reserveUsernameHash(aci, List.of(TestRandomUtil.nextBytes(32))),
          "the first set after re-registering is the one free set; the next change must wait for the cooldown");
      assertEquals(Duration.ofDays(180), e.getRetryAfter());
    } finally {
      clock.unpin();
    }
  }

  @Test
  void afterDeletionOneNewNameIsFreeAndTheNextOneWaitsForTheCooldown() throws Exception {
    clock.pin(Instant.ofEpochSecond(clock.instant().getEpochSecond()));
    try {
      deleteAccountInsideTheCooldown("+18005551111");
      clock.pin(clock.instant().plus(Duration.ofDays(2)));

      final Account reRegistered = AccountsHelper.createAccount(accountsManager, "+18005551111");

      // A new name, although the deleted account was inside its cooldown: the one free set.
      final byte[] newName = TestRandomUtil.nextBytes(32);
      final Account renamed = assertDoesNotThrow(() -> setUsername(reRegistered, newName),
          "the first username set after deleting and re-registering is free of the cooldown");

      final UUID aci = renamed.getAccountIdentifier();
      final UsernameChangeCooldownException e = assertThrows(UsernameChangeCooldownException.class,
          () -> accountsManager.reserveUsernameHash(aci, List.of(TestRandomUtil.nextBytes(32))),
          "a second new name right after the free set must get the cooldown");
      assertEquals(Duration.ofDays(180), e.getRetryAfter());

      // The pre-deletion name is still held for this account (30 days from the deletion), so like any of its own held
      // names it can be taken back inside the cooldown (ADR-0066 §6.2).
      final Account back = assertDoesNotThrow(() -> setUsername(renamed, USERNAME_HASH_2));
      assertArrayEquals(USERNAME_HASH_2, back.getUsernameHash().orElseThrow());
    } finally {
      clock.unpin();
    }
  }

  /// No deletion (换机 / 恢复): the cooldown is inherited as before, but the name being reclaimed can go through the
  /// client's reserve → confirm, not only a direct confirm.
  @Test
  void reRegisteringWithoutDeletionCanReserveTheNameItIsReclaimingDuringTheCooldown() throws Exception {
    Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
    account = setUsername(account, USERNAME_HASH_1);
    account = setUsername(account, USERNAME_HASH_2);

    final Account reclaimed = AccountsHelper.createAccount(accountsManager, "+18005551111");
    assertEquals(account.getAccountIdentifier(), reclaimed.getAccountIdentifier());

    final UUID aci = reclaimed.getAccountIdentifier();
    assertThrows(UsernameChangeCooldownException.class,
        () -> accountsManager.reserveUsernameHash(aci, List.of(TestRandomUtil.nextBytes(32))),
        "re-registering without a deletion still inherits the cooldown for new names");

    final Account restored = assertDoesNotThrow(() -> setUsername(reclaimed, USERNAME_HASH_2),
        "reserve → confirm of the name this re-registration is reclaiming");
    assertArrayEquals(USERNAME_HASH_2, restored.getUsernameHash().orElseThrow());
  }

  // ── Tellomi (owner 2026-09-27): the rename cooldown is 180 days; the old-name hold stays 30 ──

  @Test
  void theRenameCooldownIs180DaysWhileTheOldNameIsHeldFor30() throws Exception {
    clock.pin(Instant.ofEpochSecond(clock.instant().getEpochSecond()));
    final Instant renamedAt = clock.instant();
    try {
      Account account = AccountsHelper.createAccount(accountsManager, "+18005551111");
      account = setUsername(account, USERNAME_HASH_1);
      account = setUsername(account, USERNAME_HASH_2);
      final UUID aci = account.getAccountIdentifier();

      clock.pin(renamedAt.plus(Duration.ofDays(179)));
      final UsernameChangeCooldownException e = assertThrows(UsernameChangeCooldownException.class,
          () -> accountsManager.reserveUsernameHash(aci, List.of(TestRandomUtil.nextBytes(32))),
          "a new name 179 days after a rename must still be refused");
      assertEquals(Duration.ofDays(1), e.getRetryAfter());

      // The hold on the old name ended on day 30: from then on taking it back is a change like any other.
      clock.pin(renamedAt.plus(Duration.ofDays(31)));
      assertThrows(UsernameChangeCooldownException.class,
          () -> accountsManager.reserveUsernameHash(aci, List.of(USERNAME_HASH_1)));

      clock.pin(renamedAt.plus(Duration.ofDays(180)));
      final byte[] next = TestRandomUtil.nextBytes(32);
      assertArrayEquals(next, accountsManager.reserveUsernameHash(aci, List.of(next)).reservedUsernameHash());
    } finally {
      clock.unpin();
    }
  }
}
