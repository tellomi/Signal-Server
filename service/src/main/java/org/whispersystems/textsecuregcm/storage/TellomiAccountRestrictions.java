/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.Metrics;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
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
///
/// 暂停时另有一条 `S = number`：`H` = `HMAC-SHA256(numberHashKey, 号码)`，`U` = 截止时间。注册接口按它拦同一号码重新注册
/// （ADR-0078 §3.3 / 第六节第 6 问）——不能只看 PNI：号码对照注销满 30 天会被删，再注册会拿到新 PNI（#1339）。
/// 表里不存号码明文；没配 numberHashKey 就不拦。
public class TellomiAccountRestrictions {

  public static final String KEY_ACCOUNT = "A";
  public static final String KEY_SORT = "S";
  public static final String CURRENT = "current";
  /// 档位：见 [Level]
  public static final String ATTR_LEVEL = "L";
  /// 截止时间（epoch 秒）；到了自动失效
  public static final String ATTR_UNTIL = "U";
  /// 案件号（《投诉举报处理规则》第三十二节：申诉时提供「对应处置编号」）；告诉当事人用
  public static final String ATTR_CASE = "C";
  /// 暂停时拦重新注册的号码条目
  public static final String NUMBER = "number";
  /// 号码的带密钥哈希（32 字节）
  public static final String ATTR_NUMBER_HASH = "H";

  /// 处置档（ADR-0078 §3.3，《服务协议》§11.1）
  public enum Level {
    /// 限制陌生人消息：非密封发送（给没有互相交换过资料密钥的人发消息）被拒；联系人照常
    STRANGER("stranger"),
    /// 限制全部发送：上一档 + 不再签发送者证书（手上的证书过期后密封发送也发不出去）
    ALL("all"),
    /// 暂停：发送同 [#ALL]；账号鉴权失败（所有设备掉线、登不上，客户端进入已注销状态），同一号码重新注册被拒。
    /// 解除后用同一号码重新注册回到同一个账号
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

  /// @param caseId 案件号；老条目没有时为 null
  public record Restriction(Level level, Instant until, @Nullable String caseId) {

    public Restriction(final Level level, final Instant until) {
      this(level, until, null);
    }
  }

  private record Snapshot(Map<UUID, Restriction> accounts, Map<String, Restriction> numbers) {
  }

  private static final String REFRESH_COUNTER_NAME = name(TellomiAccountRestrictions.class, "refresh");
  private static final Logger logger = LoggerFactory.getLogger(TellomiAccountRestrictions.class);

  private final DynamoDbClient dynamoDbClient;
  private final String tableName;
  @Nullable
  private final byte[] numberHashKey;
  private final Clock clock;

  private volatile Snapshot snapshot = new Snapshot(Map.of(), Map.of());
  private volatile Consumer<UUID> onSuspended = _ -> {};

  public TellomiAccountRestrictions(final DynamoDbClient dynamoDbClient, final String tableName, final Clock clock) {
    this(dynamoDbClient, tableName, null, clock);
  }

  public TellomiAccountRestrictions(final DynamoDbClient dynamoDbClient, final String tableName,
      @Nullable final byte[] numberHashKey, final Clock clock) {
    this.dynamoDbClient = dynamoDbClient;
    this.tableName = tableName;
    this.numberHashKey = numberHashKey;
    this.clock = clock;
  }

  /// 刷新后发现某个账号刚变成「暂停」时调一次（用来断开它所有设备的连接）。要在 [#start] 之前设。
  public void onSuspended(final Consumer<UUID> listener) {
    this.onSuspended = listener;
  }

  /// 现在对这个账号有效的处置；没有、或者已经过了截止时间就是空。
  public Optional<Restriction> get(final UUID accountIdentifier) {
    final Restriction restriction = snapshot.accounts().get(accountIdentifier);
    if (restriction == null || !restriction.until().isAfter(clock.instant())) {
      return Optional.empty();
    }
    return Optional.of(restriction);
  }

  public boolean isSuspended(final UUID accountIdentifier) {
    return get(accountIdentifier).map(restriction -> restriction.level() == Level.SUSPENDED).orElse(false);
  }

  /// 这个号码被暂停拦着重新注册的话，是哪一条（档位固定是暂停）。没配 numberHashKey 时永远是空。
  public Optional<Restriction> numberBlock(final String e164) {
    if (numberHashKey == null) {
      return Optional.empty();
    }
    final Restriction block = snapshot.numbers().get(HexFormat.of().formatHex(numberHash(numberHashKey, e164)));
    return block != null && block.until().isAfter(clock.instant()) ? Optional.of(block) : Optional.empty();
  }

  /// `HMAC-SHA256(key, 号码的 UTF-8)`；香港 `deploy/hk/restrict.py` 用同一个算法写条目。
  public static byte[] numberHash(final byte[] key, final String e164) {
    try {
      final Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(e164.getBytes(StandardCharsets.UTF_8));
    } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  /// 整表读一遍、换掉内存里的名单。读失败时保留上一份（名单不会因为一次读失败被清空）。
  public void refresh() {
    try {
      final Map<UUID, Restriction> fresh = new HashMap<>();
      final Map<String, Restriction> numbers = new HashMap<>();
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
          parseNumber(item, now).ifPresent(entry -> numbers.merge(entry.getKey(), entry.getValue(),
              (a, b) -> a.until().isAfter(b.until()) ? a : b));
        }
        startKey = page.hasLastEvaluatedKey() && !page.lastEvaluatedKey().isEmpty() ? page.lastEvaluatedKey() : null;
      } while (startKey != null);
      final Snapshot previous = snapshot;
      snapshot = new Snapshot(Map.copyOf(fresh), Map.copyOf(numbers));
      Metrics.counter(REFRESH_COUNTER_NAME, "success", "true").increment();
      fresh.forEach((account, restriction) -> {
        final Restriction before = previous.accounts().get(account);
        if (restriction.level() == Level.SUSPENDED && (before == null || before.level() != Level.SUSPENDED)) {
          try {
            onSuspended.accept(account);
          } catch (final RuntimeException e) {
            logger.warn("Failed to handle a new suspension: {}", e.getClass().getSimpleName());
          }
        }
      });
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
      return Optional.of(Map.entry(account, new Restriction(level.get(), until, caseId(item))));
    } catch (final RuntimeException e) {
      return Optional.empty();
    }
  }

  @Nullable
  private static String caseId(final Map<String, AttributeValue> item) {
    final AttributeValue value = item.get(ATTR_CASE);
    return value != null && value.s() != null && !value.s().isBlank() ? value.s() : null;
  }

  static Optional<Map.Entry<String, Restriction>> parseNumber(final Map<String, AttributeValue> item, final Instant now) {
    try {
      if (!NUMBER.equals(item.get(KEY_SORT).s())) {
        return Optional.empty();
      }
      final byte[] hash = item.get(ATTR_NUMBER_HASH).b().asByteArray();
      final Instant until = Instant.ofEpochSecond(Long.parseLong(item.get(ATTR_UNTIL).n()));
      if (hash.length != 32 || !until.isAfter(now)) {
        return Optional.empty();
      }
      return Optional.of(Map.entry(HexFormat.of().formatHex(hash), new Restriction(Level.SUSPENDED, until, caseId(item))));
    } catch (final RuntimeException e) {
      return Optional.empty();
    }
  }
}
