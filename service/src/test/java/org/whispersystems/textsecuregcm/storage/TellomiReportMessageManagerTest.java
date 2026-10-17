/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;

/// Tellomi（ADR-0078 §3.1）：每次举报都留一条记录——服务端核实过的（found）和没核实的都记，上游的监听器照旧只听核实过的。
/// 用模拟的 Redis，不依赖 RedisClusterExtension（这台机器没有容器）。
class TellomiReportMessageManagerTest {

  private ReportMessageDynamoDb reportMessageDynamoDb;
  private TellomiReports tellomiReports;
  private ReportedMessageListener listener;
  private ReportMessageManager reportMessageManager;

  private final UUID sourceAci = UUID.randomUUID();
  private final UUID reporter = UUID.randomUUID();

  @BeforeEach
  void setUp() {
    reportMessageDynamoDb = mock(ReportMessageDynamoDb.class);
    tellomiReports = mock(TellomiReports.class);
    when(tellomiReports.record(any(), any(), anyBoolean(), anyBoolean(), any()))
        .thenReturn(CompletableFuture.completedFuture(null));
    listener = mock(ReportedMessageListener.class);

    reportMessageManager = new ReportMessageManager(reportMessageDynamoDb, mock(FaultTolerantRedisClusterClient.class),
        Duration.ofDays(1));
    reportMessageManager.addListener(listener);
  }

  private void report(final boolean deleted) {
    reportMessageManager.report(Optional.of("+15105551111"), sourceAci, Optional.of(UUID.randomUUID()), UUID.randomUUID(),
        reporter, Optional.empty(), "Signal-Android/0.1.22", deleted);
  }

  @Test
  void verifiedReportIsRecorded() {
    reportMessageManager.setTellomiReports(tellomiReports);
    when(reportMessageDynamoDb.remove(any())).thenReturn(true);

    report(false);

    verify(tellomiReports).record(sourceAci, reporter, true, false, "Signal-Android/0.1.22");
    verify(listener).handleMessageReported(any(), any(), any(), any(), anyBoolean());
  }

  @Test
  void unverifiedReportIsRecordedButListenersAreNotCalled() {
    reportMessageManager.setTellomiReports(tellomiReports);
    when(reportMessageDynamoDb.remove(any())).thenReturn(false);

    report(true);

    verify(tellomiReports).record(sourceAci, reporter, false, true, "Signal-Android/0.1.22");
    verify(listener, never()).handleMessageReported(any(), any(), any(), any(), anyBoolean());
  }

  @Test
  void withoutConfigurationNothingIsRecorded() {
    when(reportMessageDynamoDb.remove(any())).thenReturn(true);

    report(false);

    verifyNoInteractions(tellomiReports);
  }
}
