/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.Metrics;
import jakarta.annotation.Nullable;
import java.time.Clock;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import org.whispersystems.textsecuregcm.util.ua.UserAgent;
import org.whispersystems.textsecuregcm.util.ua.UserAgentUtil;
import software.amazon.awssdk.services.dynamodb.DynamoDbAsyncClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.PutItemRequest;

/// Tellomi（ADR-0078 §3.1，tellomi/tellomi#1368）：每一次「举报垃圾消息」留一条记录，给人工查看用（香港 `deploy/hk/report-queue.py`）。
///
/// 上游的举报只进 Redis 的 HyperLogLog（1 天过期，香港的 Valkey 还不落盘），没有任何人看。这里记下：
///
/// - 被举报的账号（分区键）、举报人、时间；
/// - 是否核实（`verified`）：服务端存过「这个账号给举报人发过这条消息」的摘要、而且这次删到了，才算核实。
///   没核实的（密封发送的消息、重复举报同一条、或者根本没发过）也记，查看时分开数，不作为处置的唯一依据（《社区规范》§30）；
/// - 被举报账号举报时是否已注销、举报人用的平台。
///
/// **不存**：消息编号（核对完就没用了）、手机号、举报令牌、IP、User-Agent 原文。每条到期（默认 180 天）由 TTL 删。
/// 记录写失败只记日志和计数，不影响举报本身，也不在日志里写任何标识。
public class TellomiReports {

  /// 分区键：被举报账号的 ACI（16 字节）
  public static final String KEY_REPORTED = "A";
  /// 排序键：举报时间（毫秒，补零到 13 位）+ `/` + 举报人 ACI，保证唯一、按时间排
  public static final String KEY_SORT = "S";
  /// 举报人的 ACI（16 字节）
  public static final String ATTR_REPORTER = "R";
  /// 是否核实
  public static final String ATTR_VERIFIED = "V";
  /// 被举报账号举报时是否已注销
  public static final String ATTR_SOURCE_DELETED = "D";
  /// 举报人平台：android / ios / desktop / unknown
  public static final String ATTR_PLATFORM = "P";
  /// 过期时间（epoch 秒），TTL 字段
  public static final String ATTR_EXPIRES = "E";

  private static final String RECORD_COUNTER_NAME = name(TellomiReports.class, "record");
  private static final Logger logger = LoggerFactory.getLogger(TellomiReports.class);

  private final DynamoDbAsyncClient dynamoDbAsyncClient;
  private final String tableName;
  private final Duration retention;
  private final Clock clock;

  public TellomiReports(final DynamoDbAsyncClient dynamoDbAsyncClient, final String tableName, final Duration retention,
      final Clock clock) {

    this.dynamoDbAsyncClient = dynamoDbAsyncClient;
    this.tableName = tableName;
    this.retention = retention;
    this.clock = clock;
  }

  /// 记一条举报。异步、尽力而为：返回的 future 永远正常完成，失败只记日志（不带任何标识）和计数。
  public CompletableFuture<Void> record(final UUID reportedAci, final UUID reporterAci, final boolean verified,
      final boolean sourceAccountDeleted, @Nullable final String reporterUserAgent) {

    final long nowMillis = clock.millis();
    final Map<String, AttributeValue> item = Map.of(
        KEY_REPORTED, AttributeValues.fromUUID(reportedAci),
        KEY_SORT, AttributeValues.fromString(sortKey(nowMillis, reporterAci)),
        ATTR_REPORTER, AttributeValues.fromUUID(reporterAci),
        ATTR_VERIFIED, AttributeValues.fromBool(verified),
        ATTR_SOURCE_DELETED, AttributeValues.fromBool(sourceAccountDeleted),
        ATTR_PLATFORM, AttributeValues.fromString(platform(reporterUserAgent)),
        ATTR_EXPIRES, AttributeValues.fromLong((nowMillis + retention.toMillis()) / 1000));

    try {
      return dynamoDbAsyncClient.putItem(PutItemRequest.builder().tableName(tableName).item(item).build())
          .handle((ignored, throwable) -> {
            Metrics.counter(RECORD_COUNTER_NAME, "verified", String.valueOf(verified),
                "success", String.valueOf(throwable == null)).increment();
            if (throwable != null) {
              logger.warn("Failed to record a report: {}", throwable.getClass().getSimpleName());
            }
            return null;
          });
    } catch (final RuntimeException e) {
      Metrics.counter(RECORD_COUNTER_NAME, "verified", String.valueOf(verified), "success", "false").increment();
      logger.warn("Failed to record a report: {}", e.getClass().getSimpleName());
      return CompletableFuture.completedFuture(null);
    }
  }

  static String sortKey(final long millis, final UUID reporterAci) {
    return String.format("%013d/%s", millis, reporterAci);
  }

  static String platform(@Nullable final String userAgent) {
    final UserAgent parsed = UserAgentUtil.maybeParseUserAgentString(userAgent);
    return parsed == null ? "unknown" : parsed.platform().name().toLowerCase();
  }
}
