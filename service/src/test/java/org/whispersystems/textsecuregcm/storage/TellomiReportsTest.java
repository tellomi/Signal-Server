/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import org.whispersystems.textsecuregcm.util.TestClock;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;
import software.amazon.awssdk.services.dynamodb.model.PutItemResponse;

/// Tellomi（ADR-0078 §3.1）：举报记录写什么、不写什么、写失败时不影响举报。
class TellomiReportsTest {

  private static final Instant NOW = Instant.parse("2026-10-17T09:00:00Z");

  private DynamoDbAsyncClient dynamoDbAsyncClient;
  private TellomiReports tellomiReports;

  @BeforeEach
  void setUp() {
    dynamoDbAsyncClient = mock(DynamoDbAsyncClient.class);
    when(dynamoDbAsyncClient.putItem(any(PutItemRequest.class)))
        .thenReturn(CompletableFuture.completedFuture(PutItemResponse.builder().build()));
    tellomiReports = new TellomiReports(dynamoDbAsyncClient, "tellomi_reports_test", Duration.ofDays(180),
        TestClock.pinned(NOW));
  }

  @Test
  void recordsWhoWasReportedByWhomAndWhenOnly() {
    final UUID reported = UUID.randomUUID();
    final UUID reporter = UUID.randomUUID();

    tellomiReports.record(reported, reporter, true, false, "Signal-Android/0.1.22 Android/36 Build/177101").join();

    final ArgumentCaptor<PutItemRequest> captor = ArgumentCaptor.forClass(PutItemRequest.class);
    verify(dynamoDbAsyncClient).putItem(captor.capture());
    final PutItemRequest request = captor.getValue();
    assertEquals("tellomi_reports_test", request.tableName());

    final Map<String, AttributeValue> item = request.item();
    // 只有这七个字段：没有消息编号、号码、举报令牌、IP、User-Agent 原文
    assertEquals(7, item.size());
    assertEquals(AttributeValues.fromUUID(reported), item.get(TellomiReports.KEY_REPORTED));
    assertEquals(String.format("%013d/%s", NOW.toEpochMilli(), reporter), item.get(TellomiReports.KEY_SORT).s());
    assertEquals(AttributeValues.fromUUID(reporter), item.get(TellomiReports.ATTR_REPORTER));
    assertTrue(item.get(TellomiReports.ATTR_VERIFIED).bool());
    assertFalse(item.get(TellomiReports.ATTR_SOURCE_DELETED).bool());
    assertEquals("android", item.get(TellomiReports.ATTR_PLATFORM).s());
    assertEquals(String.valueOf(NOW.plus(Duration.ofDays(180)).getEpochSecond()), item.get(TellomiReports.ATTR_EXPIRES).n());
  }

  @Test
  void unverifiedReportsAndUnknownClientsAreRecordedToo() {
    tellomiReports.record(UUID.randomUUID(), UUID.randomUUID(), false, true, null).join();

    final ArgumentCaptor<PutItemRequest> captor = ArgumentCaptor.forClass(PutItemRequest.class);
    verify(dynamoDbAsyncClient).putItem(captor.capture());
    final Map<String, AttributeValue> item = captor.getValue().item();
    assertFalse(item.get(TellomiReports.ATTR_VERIFIED).bool());
    assertTrue(item.get(TellomiReports.ATTR_SOURCE_DELETED).bool());
    assertEquals("unknown", item.get(TellomiReports.ATTR_PLATFORM).s());
  }

  @Test
  void platforms() {
    assertEquals("ios", TellomiReports.platform("Signal-iOS/0.1.0 iOS/26.5 Build/20"));
    assertEquals("desktop", TellomiReports.platform("Signal-Desktop/0.1.14 macOS/26"));
    assertEquals("unknown", TellomiReports.platform("curl/8.0"));
    assertEquals("unknown", TellomiReports.platform(""));
  }

  @Test
  void sortKeysOrderByTime() {
    final UUID reporter = UUID.randomUUID();
    assertTrue(TellomiReports.sortKey(999L, reporter).compareTo(TellomiReports.sortKey(1000L, reporter)) < 0);
    assertTrue(TellomiReports.sortKey(1000L, reporter).compareTo(TellomiReports.sortKey(NOW.toEpochMilli(), reporter)) < 0);
  }

  @Test
  void aFailedWriteDoesNotFailTheReport() {
    when(dynamoDbAsyncClient.putItem(any(PutItemRequest.class)))
        .thenReturn(CompletableFuture.failedFuture(new RuntimeException("boom")));
    assertDoesNotThrow(() -> tellomiReports.record(UUID.randomUUID(), UUID.randomUUID(), true, false, null).join());

    when(dynamoDbAsyncClient.putItem(any(PutItemRequest.class))).thenThrow(new IllegalStateException("client closed"));
    assertDoesNotThrow(() -> tellomiReports.record(UUID.randomUUID(), UUID.randomUUID(), true, false, null).join());
  }
}
