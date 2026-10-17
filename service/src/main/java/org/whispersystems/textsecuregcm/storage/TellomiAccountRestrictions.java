/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.Metrics;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.util.AttributeValues;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.awssdk.services.dynamodb.model.ScanRequest;
import software.amazon.awssdk.services.dynamodb.model.ScanResponse;

/// Tellomi（ADR-0078 §3.3 第二刀，tellomi/tellomi#1368）：被人工处置的账号名单。
///
/// 名单由人在香港用 `deploy/hk/restrict.py` 改（每次改都在同一张表里追加一条处置记录）；服务端只读，
/// 每 [#refresh] 一遍（默认一分钟）整表读进内存，发消息时查内存，不在发送路径上读库。
///
/// 一个账号一条现行记录：分区键 `A` = ACI，排序键 `S` = `current`；处置记录 `S` = `h/<毫秒>`，服务端不读。
public class TellomiAccountRestrictions {

  public static final String KEY_ACCOUNT = "A";
  public static final String KEY_SORT = "S";
  public static final String CURRENT = "current";
  /// 档位：见 [Level]
  public static final String ATTR_LEVEL = "L";
  /// 截止时间（epoch 秒）；到了自动失效
  public static final String ATTR_UNTIL = "U";

  /// 处置档（ADR-0078 §3.3，《服务协议》§11.1）
  public enum Level {
    /// 限制陌生人消息：非密封发送（给没有互相交换过资料密钥的人发消息）被拒；联系人照常
    STRANGER("stranger"),
    /// 限制全部发送：上一档 + 不再签发送者证书（手上的证书过期后密封发送也发不出去）
    ALL("all"),
    /// 暂停：发送同 [#ALL]；锁账号与同号重新注册拦截在第二刀后半（2b）
    SUSPENDED("suspended");

    private final String code;

    Level(final String code) {
      this.code = code;
    }

    public String code() {
      return code;
    }

    public boolean blocksSenderCertificates() {
      return this != STRANGER;
    }

    static Optional<Level> fromCode(final String code) {
      for (final Level level : values()) {
        if (level.code.equals(code)) {
          return Optional.of(level);
        }
      }
      return Optional.empty();
    }
  }

  public record Restriction(Level level, Instant until) {
  }

  private static final String REFRESH_COUNTER_NAME = name(TellomiAccountRestrictions.class, "refresh");
  private static final Logger logger = LoggerFactory.getLogger(TellomiAccountRestrictions.class);

  private final DynamoDbClient dynamoDbClient;
  private final String tableName;
  private final Clock clock;

  private volatile Map<UUID, Restriction> restrictions = Map.of();

  public TellomiAccountRestrictions(final DynamoDbClient dynamoDbClient, final String tableName, final Clock clock) {
    this.dynamoDbClient = dynamoDbClient;
    this.tableName = tableName;
    this.clock = clock;
  }

  /// 现在对这个账号有效的处置；没有、或者已经过了截止时间就是空。
  public Optional<Restriction> get(final UUID accountIdentifier) {
    final Restriction restriction = restrictions.get(accountIdentifier);
    if (restriction == null || !restriction.until().isAfter(clock.instant())) {
      return Optional.empty();
    }
    return Optional.of(restriction);
  }

  /// 整表读一遍、换掉内存里的名单。读失败时保留上一份（名单不会因为一次读失败被清空）。
  public void refresh() {
    try {
      final Map<UUID, Restriction> fresh = new HashMap<>();
      final Instant now = clock.instant();
      Map<String, AttributeValue> startKey = null;
      do {
        final ScanResponse page = dynamoDbClient.scan(ScanRequest.builder()
            .tableName(tableName)
            .consistentRead(true)
            .exclusiveStartKey(startKey)
            .build());
        for (final Map<String, AttributeValue> item : page.items()) {
          parse(item, now).ifPresent(entry -> fresh.put(entry.getKey(), entry.getValue()));
        }
        startKey = page.hasLastEvaluatedKey() && !page.lastEvaluatedKey().isEmpty() ? page.lastEvaluatedKey() : null;
      } while (startKey != null);
      restrictions = Map.copyOf(fresh);
      Metrics.counter(REFRESH_COUNTER_NAME, "success", "true").increment();
    } catch (final RuntimeException e) {
      Metrics.counter(REFRESH_COUNTER_NAME, "success", "false").increment();
      logger.warn("Failed to refresh account restrictions: {}", e.getClass().getSimpleName());
    }
  }

  public void start(final ScheduledExecutorService executor, final Duration interval) {
    refresh();
    executor.scheduleWithFixedDelay(this::refresh, interval.toMillis(), interval.toMillis(), TimeUnit.MILLISECONDS);
  }

  static Optional<Map.Entry<UUID, Restriction>> parse(final Map<String, AttributeValue> item, final Instant now) {
    try {
      if (!CURRENT.equals(item.get(KEY_SORT).s())) {
        return Optional.empty();
      }
      final UUID account = AttributeValues.getUUID(item, KEY_ACCOUNT, null);
      final Optional<Level> level = Level.fromCode(item.get(ATTR_LEVEL).s());
      final Instant until = Instant.ofEpochSecond(Long.parseLong(item.get(ATTR_UNTIL).n()));
      if (account == null || level.isEmpty() || !until.isAfter(now)) {
        return Optional.empty();
      }
      return Optional.of(Map.entry(account, new Restriction(level.get(), until)));
    } catch (final RuntimeException e) {
      return Optional.empty();
    }
  }
}
