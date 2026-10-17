/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions.Level;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import org.whispersystems.textsecuregcm.util.TestClock;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;

/// Tellomi（ADR-0078 §3.3）：处置名单的读取规则——只认现行记录、过了截止时间就失效、读失败保留上一份。
class TellomiAccountRestrictionsTest {

  private static final Instant NOW = Instant.parse("2026-10-17T10:00:00Z");

  private DynamoDbClient dynamoDbClient;
  private TestClock clock;
  private TellomiAccountRestrictions restrictions;

  @BeforeEach
  void setUp() {
    dynamoDbClient = mock(DynamoDbClient.class);
    clock = TestClock.pinned(NOW);
    restrictions = new TellomiAccountRestrictions(dynamoDbClient, "tellomi_account_restrictions_test", clock);
  }

  private static Map<String, AttributeValue> item(final UUID account, final String sort, final String level,
      final Instant until) {
    return Map.of(
        TellomiAccountRestrictions.KEY_ACCOUNT, AttributeValues.fromUUID(account),
        TellomiAccountRestrictions.KEY_SORT, AttributeValues.fromString(sort),
        TellomiAccountRestrictions.ATTR_LEVEL, AttributeValues.fromString(level),
        TellomiAccountRestrictions.ATTR_UNTIL, AttributeValues.fromLong(until.getEpochSecond()));
  }

  @Test
  void onlyCurrentUnexpiredWellFormedRecordsCount() {
    final UUID stranger = UUID.randomUUID(), all = UUID.randomUUID(), expired = UUID.randomUUID(), history = UUID.randomUUID();
    when(dynamoDbClient.scan(any(ScanRequest.class))).thenReturn(ScanResponse.builder().items(List.of(
        item(stranger, "current", "stranger", NOW.plus(Duration.ofDays(7))),
        item(all, "current", "all", NOW.plus(Duration.ofDays(30))),
        item(expired, "current", "stranger", NOW.minusSeconds(1)),
        item(history, "h/1792000000000", "all", NOW.plus(Duration.ofDays(30))),
        item(UUID.randomUUID(), "current", "something-else", NOW.plus(Duration.ofDays(1))),
        Map.of("A", AttributeValues.fromString("not-a-uuid"))
    )).build());

    restrictions.refresh();

    assertEquals(Level.STRANGER, restrictions.get(stranger).orElseThrow().level());
    assertEquals(Level.ALL, restrictions.get(all).orElseThrow().level());
    assertTrue(restrictions.get(expired).isEmpty());
    assertTrue(restrictions.get(history).isEmpty());
    assertTrue(restrictions.get(UUID.randomUUID()).isEmpty());
  }

  @Test
  void aRestrictionLapsesAtItsDeadlineWithoutARefresh() {
    final UUID account = UUID.randomUUID();
    when(dynamoDbClient.scan(any(ScanRequest.class))).thenReturn(ScanResponse.builder()
        .items(List.of(item(account, "current", "stranger", NOW.plus(Duration.ofHours(1))))).build());
    restrictions.refresh();
    assertTrue(restrictions.get(account).isPresent());

    clock.pin(NOW.plus(Duration.ofHours(1)));
    assertTrue(restrictions.get(account).isEmpty());
  }

  @Test
  void pagesAreFollowed() {
    final UUID first = UUID.randomUUID(), second = UUID.randomUUID();
    when(dynamoDbClient.scan(any(ScanRequest.class)))
        .thenReturn(ScanResponse.builder()
            .items(List.of(item(first, "current", "all", NOW.plus(Duration.ofDays(1)))))
            .lastEvaluatedKey(Map.of("A", AttributeValues.fromUUID(first)))
            .build())
        .thenReturn(ScanResponse.builder()
            .items(List.of(item(second, "current", "stranger", NOW.plus(Duration.ofDays(1)))))
            .build());

    restrictions.refresh();

    assertTrue(restrictions.get(first).isPresent());
    assertTrue(restrictions.get(second).isPresent());
  }

  @Test
  void aFailedRefreshKeepsTheLastList() {
    final UUID account = UUID.randomUUID();
    when(dynamoDbClient.scan(any(ScanRequest.class)))
        .thenReturn(ScanResponse.builder().items(List.of(item(account, "current", "all", NOW.plus(Duration.ofDays(1))))).build())
        .thenThrow(new IllegalStateException("table gone"));

    restrictions.refresh();
    restrictions.refresh();

    assertTrue(restrictions.get(account).isPresent());
  }

  private static final byte[] KEY = new byte[32];

  private static Map<String, AttributeValue> numberItem(final UUID account, final byte[] hash, final Instant until) {
    return Map.of(
        TellomiAccountRestrictions.KEY_ACCOUNT, AttributeValues.fromUUID(account),
        TellomiAccountRestrictions.KEY_SORT, AttributeValues.fromString(TellomiAccountRestrictions.NUMBER),
        TellomiAccountRestrictions.ATTR_NUMBER_HASH, AttributeValues.fromByteArray(hash),
        TellomiAccountRestrictions.ATTR_UNTIL, AttributeValues.fromLong(until.getEpochSecond()),
        TellomiAccountRestrictions.ATTR_CASE, AttributeValues.fromString("case-7"));
  }

  @Test
  void theCaseIdTravelsWithTheRestrictionWhenPresent() {
    final UUID withCase = UUID.randomUUID(), withoutCase = UUID.randomUUID();
    final Map<String, AttributeValue> item = new java.util.HashMap<>(item(withCase, "current", "all", NOW.plus(Duration.ofDays(30))));
    item.put(TellomiAccountRestrictions.ATTR_CASE, AttributeValues.fromString("20261017-abcd1234"));
    when(dynamoDbClient.scan(any(ScanRequest.class))).thenReturn(ScanResponse.builder().items(List.of(
        item, item(withoutCase, "current", "all", NOW.plus(Duration.ofDays(30))))).build());

    restrictions.refresh();

    assertEquals("20261017-abcd1234", restrictions.get(withCase).orElseThrow().caseId());
    assertEquals(null, restrictions.get(withoutCase).orElseThrow().caseId());
  }

  @Test
  void suspendedNumbersAreMatchedByTheirKeyedHashUntilTheDeadline() {
    final TellomiAccountRestrictions withKey =
        new TellomiAccountRestrictions(dynamoDbClient, "tellomi_account_restrictions_test", KEY, clock);
    final UUID account = UUID.randomUUID();
    when(dynamoDbClient.scan(any(ScanRequest.class))).thenReturn(ScanResponse.builder().items(List.of(
        item(account, "current", "suspended", NOW.plus(Duration.ofDays(30))),
        numberItem(account, TellomiAccountRestrictions.numberHash(KEY, "+8613800000003"), NOW.plus(Duration.ofDays(30))),
        numberItem(UUID.randomUUID(), TellomiAccountRestrictions.numberHash(KEY, "+8613800000004"), NOW.minusSeconds(1)),
        numberItem(UUID.randomUUID(), new byte[7], NOW.plus(Duration.ofDays(30)))
    )).build());

    withKey.refresh();

    assertTrue(withKey.isSuspended(account));
    assertEquals(NOW.plus(Duration.ofDays(30)), withKey.numberBlock("+8613800000003").orElseThrow().until());
    assertEquals("case-7", withKey.numberBlock("+8613800000003").orElseThrow().caseId());
    assertTrue(withKey.numberBlock("+8613800000004").isEmpty(), "expired");
    assertTrue(withKey.numberBlock("+8613800000005").isEmpty(), "never blocked");

    clock.pin(NOW.plus(Duration.ofDays(30)));
    assertTrue(withKey.numberBlock("+8613800000003").isEmpty(), "lapses at the deadline");
  }

  @Test
  void withoutAKeyNoNumberIsEverBlocked() {
    when(dynamoDbClient.scan(any(ScanRequest.class))).thenReturn(ScanResponse.builder().items(List.of(
        numberItem(UUID.randomUUID(), TellomiAccountRestrictions.numberHash(KEY, "+8613800000003"), NOW.plus(Duration.ofDays(30)))
    )).build());
    restrictions.refresh();
    assertTrue(restrictions.numberBlock("+8613800000003").isEmpty());
  }

  @Test
  void theNumberHashIsHmacSha256OfTheUtf8Number() {
    // 和 deploy/hk/test/restrict_test.py 的同一个向量：hmac.new(bytes(32), b"+8613800000003", sha256)
    assertEquals("092bd595cdb5fc287a5a15ee58d7cb43f08f12a070f846da3ffad9c2ed51eea2",
        java.util.HexFormat.of().formatHex(TellomiAccountRestrictions.numberHash(KEY, "+8613800000003")));
  }

  @Test
  void aNewSuspensionIsReportedOnce() {
    final UUID account = UUID.randomUUID();
    final List<UUID> suspended = new java.util.ArrayList<>();
    restrictions.onSuspended(suspended::add);
    when(dynamoDbClient.scan(any(ScanRequest.class)))
        .thenReturn(ScanResponse.builder().items(List.of(item(account, "current", "stranger", NOW.plus(Duration.ofDays(7))))).build())
        .thenReturn(ScanResponse.builder().items(List.of(item(account, "current", "suspended", NOW.plus(Duration.ofDays(7))))).build())
        .thenReturn(ScanResponse.builder().items(List.of(item(account, "current", "suspended", NOW.plus(Duration.ofDays(7))))).build());

    restrictions.refresh();
    assertTrue(suspended.isEmpty());
    restrictions.refresh();
    assertEquals(List.of(account), suspended);
    restrictions.refresh();
    assertEquals(List.of(account), suspended, "still suspended: no second disconnect");
  }

  @Test
  void onlyTheHarderLevelsBlockSenderCertificates() {
    assertFalse(Level.STRANGER.blocksSenderCertificates());
    assertTrue(Level.ALL.blocksSenderCertificates());
    assertTrue(Level.SUSPENDED.blocksSenderCertificates());
  }
}
