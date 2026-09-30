/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import com.google.common.net.InetAddresses;
import io.lettuce.core.KeyValue;
import io.lettuce.core.ScriptOutputType;
import io.lettuce.core.SetArgs;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.whispersystems.textsecuregcm.redis.ClusterLuaScript;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;

/// ADR-0070 §6.2 的计数：放在限流用的 Redis 集群里（和 ALTCHA 的一次性记录、网段签发计数同一套），**不落数据库**。
///
/// **隐私**（§6.2）：键里没有任何明文——IP、网段、号码、号段、会话号都先做带密钥的哈希（HMAC-SHA256，取前 16 字节），
/// 密钥由配置里的 `secret` 派生；每个键都带过期时间，最长 24 小时（用 Lua 脚本把「加 1」和「设过期」放在同一步，不会漏设）。
///
/// **窗口**：按整点桶计数。24 小时窗口读最近 24 个整点桶（实际覆盖 23–24 小时）；1 小时窗口读当前桶和上一个桶，
/// 上一个桶按剩余比例加权（和 ALTCHA 的网段计数同一种滑动估计）。键的形状：
/// `regrisk::<种类>::{<哈希>}::<整点桶>`，花括号是 Redis Cluster 的 hash tag，同一个实体的所有桶落在同一个槽，一条 `MGET` 读完。
///
/// 所有 Redis 出错统一包成 [RiskUnavailableException]，由调用方 fail-open。
final class RegistrationRiskCounters {

  private static final String KEY_PREFIX = "regrisk::";
  private static final long HOUR_SECONDS = 3600;
  private static final int DAY_HOURS = 24;

  /// 24 小时窗口的桶：整个桶最晚在窗口读完它之后才过期，最长 24 小时（从创建算起）
  static final long DAY_BUCKET_TTL_SECONDS = DAY_HOURS * HOUR_SECONDS;
  /// 1 小时窗口要读到上一个桶，所以桶活 2 小时
  static final long HOUR_BUCKET_TTL_SECONDS = 2 * HOUR_SECONDS;
  /// 会话分组标记：远端会话本身只活十来分钟，留 1 小时余量
  static final long COHORT_TTL_SECONDS = HOUR_SECONDS;

  private static final String SUBNET_SESSIONS = "sub-sess";
  private static final String IP_SESSIONS = "ip-sess";
  private static final String NUMBER_SESSIONS = "num-sess";
  private static final String NUMBER_CODES = "num-code";
  private static final String PREFIX_SENT = "seg-sent";
  private static final String PREFIX_VERIFIED = "seg-ok";
  private static final String WOULD_ALLOW = "allow";
  private static final String COHORT_SENT = "coh-sent";
  private static final String COHORT_VERIFIED = "coh-ok";
  private static final String COHORT_FLAG = "coh";
  /// 全局计数没有实体，用固定的 hash tag
  private static final String GLOBAL = "g";

  private final FaultTolerantRedisClusterClient redisCluster;
  private final ClusterLuaScript incrementScript;
  private final byte[] hashKey;
  private final Clock clock;

  /// 一次评估涉及的实体（都是哈希，不是明文）。来源地址解析不了、号码解析不了号段时对应的哈希为 null，那几项计数就跳过
  record Entities(@Nullable String subnet, @Nullable String ip, String number, @Nullable String prefix, String session) {
  }

  RegistrationRiskCounters(final FaultTolerantRedisClusterClient redisCluster, final String secret, final Clock clock) {
    this.redisCluster = redisCluster;
    this.clock = clock;
    this.hashKey = hmac(secret.getBytes(StandardCharsets.UTF_8), "tellomi-registration-risk/counter-key");

    try {
      this.incrementScript = ClusterLuaScript.fromResource(redisCluster, "lua/tellomi_risk_incr.lua",
          ScriptOutputType.INTEGER);
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  /// 只做哈希，不碰 Redis
  Entities entities(final RiskSignals signals) {
    final InetAddress address = RiskRules.parseAddress(signals.sourceAddress()).orElse(null);

    return new Entities(
        address == null ? null : hash("subnet", RiskRules.subnetOf(address)),
        address == null ? null : hash("ip", InetAddresses.toAddrString(address)),
        hash("number", signals.e164()),
        RiskRules.segmentOf(signals.e164()).map(segment -> hash("prefix", segment)).orElse(null),
        hash("session", signals.sessionId()));
  }

  /// 建会话：网段、IP、号码的 24 小时会话数各加 1
  void recordSession(final Entities entities) {
    final long hour = currentHour();
    call(() -> {
      if (entities.subnet() != null) {
        increment(SUBNET_SESSIONS, entities.subnet(), DAY_BUCKET_TTL_SECONDS, hour);
      }
      if (entities.ip() != null) {
        increment(IP_SESSIONS, entities.ip(), DAY_BUCKET_TTL_SECONDS, hour);
      }
      increment(NUMBER_SESSIONS, entities.number(), DAY_BUCKET_TTL_SECONDS, hour);
      return null;
    });
  }

  /// 验证码发出去了：号码的 24 小时发码数、号段的 1 小时发码数各加 1
  void recordCodeSent(final Entities entities) {
    final long hour = currentHour();
    call(() -> {
      increment(NUMBER_CODES, entities.number(), DAY_BUCKET_TTL_SECONDS, hour);
      if (entities.prefix() != null) {
        increment(PREFIX_SENT, entities.prefix(), HOUR_BUCKET_TTL_SECONDS, hour);
      }
      return null;
    });
  }

  /// 验证码验对了：号段的 1 小时验证成功数加 1
  void recordVerified(final Entities entities) {
    final long hour = currentHour();
    call(() -> {
      if (entities.prefix() != null) {
        increment(PREFIX_VERIFIED, entities.prefix(), HOUR_BUCKET_TTL_SECONDS, hour);
      }
      return null;
    });
  }

  /// 全局：这个整点小时又多了一个「本来会放行」的会话
  void recordWouldAllow() {
    final long hour = currentHour();
    call(() -> increment(WOULD_ALLOW, GLOBAL, HOUR_BUCKET_TTL_SECONDS, hour));
  }

  /// 「本来会放行」那一组会话的发码数 / 验证成功数（1 小时窗口）
  void recordCohortSent() {
    final long hour = currentHour();
    call(() -> increment(COHORT_SENT, GLOBAL, HOUR_BUCKET_TTL_SECONDS, hour));
  }

  void recordCohortVerified() {
    final long hour = currentHour();
    call(() -> increment(COHORT_VERIFIED, GLOBAL, HOUR_BUCKET_TTL_SECONDS, hour));
  }

  /// 记下这个会话在建会话那一刻被评估成哪一组，后面发码 / 验码的事件靠它归组
  void setCohort(final Entities entities, final RiskCohort cohort) {
    call(() -> redisCluster.withCluster(connection ->
        connection.sync().set(cohortKey(entities), cohort.flag(), SetArgs.Builder.ex(COHORT_TTL_SECONDS))));
  }

  Optional<RiskCohort> cohort(final Entities entities) {
    return call(() -> RiskCohort.fromFlag(
        redisCluster.withCluster(connection -> connection.sync().get(cohortKey(entities)))));
  }

  /// 读出评估要用的全部计数
  RiskSnapshot read(final Entities entities) {
    final long epochSecond = clock.instant().getEpochSecond();
    final long hour = epochSecond / HOUR_SECONDS;
    final double elapsedFraction = (double) (epochSecond % HOUR_SECONDS) / HOUR_SECONDS;

    return call(() -> new RiskSnapshot(
        entities.subnet() == null ? 0 : dayCount(SUBNET_SESSIONS, entities.subnet(), hour),
        entities.ip() == null ? 0 : dayCount(IP_SESSIONS, entities.ip(), hour),
        dayCount(NUMBER_SESSIONS, entities.number(), hour),
        dayCount(NUMBER_CODES, entities.number(), hour),
        entities.prefix() == null ? 0 : slidingHourCount(PREFIX_SENT, entities.prefix(), hour, elapsedFraction),
        entities.prefix() == null ? 0 : slidingHourCount(PREFIX_VERIFIED, entities.prefix(), hour, elapsedFraction),
        counts(List.of(key(WOULD_ALLOW, GLOBAL, hour)))[0],
        slidingHourCount(COHORT_SENT, GLOBAL, hour, elapsedFraction),
        slidingHourCount(COHORT_VERIFIED, GLOBAL, hour, elapsedFraction)));
  }

  private long dayCount(final String kind, final String hash, final long hour) {
    final List<String> keys = new ArrayList<>(DAY_HOURS);
    for (long bucket = hour - (DAY_HOURS - 1); bucket <= hour; bucket++) {
      keys.add(key(kind, hash, bucket));
    }
    long total = 0;
    for (final long count : counts(keys)) {
      total += count;
    }
    return total;
  }

  private long slidingHourCount(final String kind, final String hash, final long hour, final double elapsedFraction) {
    final long[] counts = counts(List.of(key(kind, hash, hour), key(kind, hash, hour - 1)));
    return counts[0] + (long) Math.floor(counts[1] * (1 - elapsedFraction));
  }

  /// 一条 `MGET`；同一个实体的桶共用 hash tag，落在同一个槽
  private long[] counts(final List<String> keys) {
    final List<KeyValue<String, String>> values =
        redisCluster.withCluster(connection -> connection.sync().mget(keys.toArray(String[]::new)));

    final long[] counts = new long[values.size()];
    for (int i = 0; i < counts.length; i++) {
      counts[i] = Long.parseLong(values.get(i).getValueOrElse("0"));
    }
    return counts;
  }

  private long increment(final String kind, final String hash, final long ttlSeconds, final long hour) {
    return (Long) incrementScript.execute(List.of(key(kind, hash, hour)), List.of(Long.toString(ttlSeconds)));
  }

  private static String key(final String kind, final String hash, final long hour) {
    return KEY_PREFIX + kind + "::{" + hash + "}::" + hour;
  }

  private static String cohortKey(final Entities entities) {
    return KEY_PREFIX + COHORT_FLAG + "::{" + entities.session() + "}";
  }

  private long currentHour() {
    return clock.instant().getEpochSecond() / HOUR_SECONDS;
  }

  /// 带密钥的哈希，取前 16 字节。`domain` 把不同种类的值隔开，同一个字符串在不同种类下哈希不同
  private String hash(final String domain, final String value) {
    return HexFormat.of().formatHex(hmac(hashKey, domain + '\0' + value), 0, 16);
  }

  private static <T> T call(final Supplier<T> action) {
    try {
      return action.get();
    } catch (final RuntimeException e) {
      throw new RiskUnavailableException(e);
    }
  }

  private static byte[] hmac(final byte[] key, final String message) {
    try {
      final Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(message.getBytes(StandardCharsets.UTF_8));
    } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError("HmacSHA256 is always available", e);
    }
  }
}
