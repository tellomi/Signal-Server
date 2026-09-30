/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.redis.RedisClusterExtension;
import org.whispersystems.textsecuregcm.registration.risk.RegistrationRiskCounters.Entities;
import org.whispersystems.textsecuregcm.util.TestClock;

/// ADR-0070 §6.2 的计数：窗口、隐私（键里没有明文）、过期。Redis 用真的（集群），和线上走同一条 Lua / MGET。
class RegistrationRiskCountersTest {

  @RegisterExtension
  static final RedisClusterExtension REDIS_CLUSTER_EXTENSION = RedisClusterExtension.builder().build();

  private static final long HOUR = 490_000L;

  private static final String IP = "203.0.113.77";
  private static final String NUMBER = "+8613800138000";
  private static final String SESSION = "c2Vzc2lvbi1pZC1wbGFpbg";

  private TestClock clock;
  private RegistrationRiskCounters counters;

  @BeforeEach
  void setUp() {
    clock = TestClock.pinned(at(HOUR, 1800));
    counters = new RegistrationRiskCounters(REDIS_CLUSTER_EXTENSION.getRedisCluster(), "secret", clock);
  }

  private static Instant at(final long hour, final long secondsIntoHour) {
    return Instant.ofEpochSecond(hour * 3600 + secondsIntoHour);
  }

  private Entities entities(final String ip, final String number, final String session) {
    return counters.entities(new RiskSignals(ip, number, "ua", session, false));
  }

  private List<String> allKeys() {
    return REDIS_CLUSTER_EXTENSION.getRedisCluster().withCluster(connection -> connection.sync().keys("*"));
  }

  private long ttl(final String key) {
    return REDIS_CLUSTER_EXTENSION.getRedisCluster().withCluster(connection -> connection.sync().ttl(key));
  }

  // 隐私：键里没有明文，全都会过期

  @Test
  void keysCarryNoPlaintextAndAllExpire() {
    final Entities entities = entities(IP, NUMBER, SESSION);

    counters.recordSession(entities);
    counters.recordCodeSent(entities);
    counters.recordVerified(entities);
    counters.recordWouldAllow();
    counters.recordCohortSent();
    counters.recordCohortVerified();
    counters.setCohort(entities, RiskCohort.WOULD_ALLOW);

    final List<String> keys = allKeys();

    // 会话：网段 / IP / 号码 3 个；发码：号码 + 号段 2 个；验对：号段 1 个；全局 3 个；会话分组 1 个
    assertThat(keys).hasSize(10);

    for (final String key : keys) {
      assertThat(key).startsWith("regrisk::")
          .as("no plaintext IP, subnet, number, national number, segment or session id in " + key)
          .doesNotContain(IP, "203.0.113", NUMBER, "13800138000", "1380013", "86138", SESSION, "c2Vzc2lvbi");

      final long ttl = ttl(key);
      assertThat(ttl).as("every key expires: " + key).isBetween(1L, RegistrationRiskCounters.DAY_BUCKET_TTL_SECONDS);
      if (key.startsWith("regrisk::coh::")) {
        assertThat(ttl).isLessThanOrEqualTo(RegistrationRiskCounters.COHORT_TTL_SECONDS);
      } else if (key.contains("::seg-") || key.contains("::allow::") || key.contains("::coh-")) {
        assertThat(ttl).isLessThanOrEqualTo(RegistrationRiskCounters.HOUR_BUCKET_TTL_SECONDS);
      }
    }

    // 实体哈希是 32 位十六进制（HMAC-SHA256 取前 16 字节），全局键用固定的 {g}
    assertThat(keys).allMatch(key -> key.matches("regrisk::[a-z-]+::\\{([0-9a-f]{32}|g)}(::\\d+)?"));
  }

  @Test
  void repeatedIncrementsDoNotExtendTheExpiry() {
    final Entities entities = entities(IP, NUMBER, SESSION);

    counters.recordSession(entities);
    final String key = allKeys().stream().filter(k -> k.startsWith("regrisk::num-sess::")).findFirst().orElseThrow();
    final long first = ttl(key);

    counters.recordSession(entities);
    counters.recordSession(entities);

    // 过期时间只在键建出来那一下设，之后的加 1 不续期（也不会因为脚本里漏设而没有过期时间）
    assertThat(ttl(key)).isPositive().isLessThanOrEqualTo(first);
    assertThat(allKeys()).allSatisfy(k -> assertThat(ttl(k)).isPositive());
  }

  @Test
  void hashesAreKeyedAndDeterministic() {
    final Entities a = entities(IP, NUMBER, SESSION);

    assertThat(entities(IP, NUMBER, SESSION)).isEqualTo(a);
    assertThat(a.number()).matches("[0-9a-f]{32}");

    // 别的密钥 → 全是别的哈希（换密钥等于计数清零）
    final RegistrationRiskCounters other = new RegistrationRiskCounters(REDIS_CLUSTER_EXTENSION.getRedisCluster(),
        "another-secret", clock);
    final Entities b = other.entities(new RiskSignals(IP, NUMBER, "ua", SESSION, false));
    assertThat(b.number()).isNotEqualTo(a.number());
    assertThat(b.ip()).isNotEqualTo(a.ip());
    assertThat(b.subnet()).isNotEqualTo(a.subnet());
    assertThat(b.prefix()).isNotEqualTo(a.prefix());
    assertThat(b.session()).isNotEqualTo(a.session());

    // 同一个字符串在不同种类下哈希不同（种类隔开）
    final Entities sameString = entities("203.0.113.77", "203.0.113.77", "203.0.113.77");
    assertThat(sameString.number()).isNotEqualTo(sameString.ip()).isNotEqualTo(sameString.session());
  }

  @Test
  void countersWithDifferentSecretsDoNotSeeEachOther() {
    final RegistrationRiskCounters other = new RegistrationRiskCounters(REDIS_CLUSTER_EXTENSION.getRedisCluster(),
        "another-secret", clock);
    final RiskSignals signals = new RiskSignals(IP, NUMBER, "ua", SESSION, false);

    counters.recordSession(counters.entities(signals));

    assertThat(counters.read(counters.entities(signals)).numberSessions24h()).isEqualTo(1);
    assertThat(other.read(other.entities(signals)).numberSessions24h()).isZero();
  }

  @Test
  void readingNeverCreatesKeys() {
    counters.read(entities(IP, NUMBER, SESSION));
    counters.cohort(entities(IP, NUMBER, SESSION));

    assertThat(allKeys()).isEmpty();
  }

  // 24 小时窗口：最近 24 个整点桶

  @Test
  void dayWindowCoversTheLast24HourBuckets() {
    final Entities entities = entities(IP, NUMBER, SESSION);

    for (final long hour : new long[]{HOUR - 24, HOUR - 23, HOUR - 1, HOUR}) {
      clock.pin(at(hour, 600));
      counters.recordSession(entities);
    }

    clock.pin(at(HOUR, 1800));
    RiskSnapshot snapshot = counters.read(entities);
    assertThat(snapshot.numberSessions24h()).as("the bucket of 24 hours ago is outside the window").isEqualTo(3);
    assertThat(snapshot.subnetSessions24h()).isEqualTo(3);
    assertThat(snapshot.ipSessions24h()).isEqualTo(3);

    // 下一个整点：23 小时前那个桶也出窗口
    clock.pin(at(HOUR + 1, 0));
    snapshot = counters.read(entities);
    assertThat(snapshot.numberSessions24h()).isEqualTo(2);
    assertThat(snapshot.subnetSessions24h()).isEqualTo(2);
  }

  @Test
  void codesSentToANumberAreCountedOverTheDay() {
    final Entities entities = entities(IP, NUMBER, SESSION);
    final Entities otherNumber = entities(IP, "+8613900139000", "other-session");

    counters.recordCodeSent(entities);
    clock.pin(at(HOUR - 5, 0));
    counters.recordCodeSent(entities);
    clock.pin(at(HOUR, 1800));

    assertThat(counters.read(entities).numberCodes24h()).isEqualTo(2);
    assertThat(counters.read(otherNumber).numberCodes24h()).isZero();

    // 24 小时之后：这个号码又是「今天还没收过码」
    clock.pin(at(HOUR + 24, 0));
    assertThat(counters.read(entities).numberCodes24h()).isZero();
  }

  @Test
  void neighboursShareTheSubnetButNotTheIp() {
    final Entities a = entities("198.51.100.1", "+8613800130001", "s1");
    final Entities b = entities("198.51.100.200", "+8613800130002", "s2");
    final Entities elsewhere = entities("198.51.101.1", "+8613800130003", "s3");

    counters.recordSession(a);
    counters.recordSession(b);
    counters.recordSession(elsewhere);

    assertThat(counters.read(a).subnetSessions24h()).isEqualTo(2);
    assertThat(counters.read(b).subnetSessions24h()).isEqualTo(2);
    assertThat(counters.read(elsewhere).subnetSessions24h()).isEqualTo(1);
    assertThat(counters.read(a).ipSessions24h()).isEqualTo(1);
    assertThat(counters.read(b).ipSessions24h()).isEqualTo(1);
  }

  @Test
  void ipv6SharesTheSlash56() {
    final Entities a = entities("2001:db8:1234:5600::1", "+8613800130001", "s1");
    final Entities b = entities("2001:db8:1234:56ff:aaaa::2", "+8613800130002", "s2");
    final Entities elsewhere = entities("2001:db8:1234:5700::1", "+8613800130003", "s3");

    counters.recordSession(a);
    counters.recordSession(b);
    counters.recordSession(elsewhere);

    assertThat(counters.read(a).subnetSessions24h()).isEqualTo(2);
    assertThat(counters.read(elsewhere).subnetSessions24h()).isEqualTo(1);
  }

  // 1 小时窗口：当前桶 + 上一个桶按剩余比例加权

  @Test
  void hourWindowWeightsThePreviousBucketByTheRemainingFraction() {
    final Entities entities = entities(IP, NUMBER, SESSION);

    clock.pin(at(HOUR - 1, 100));
    for (int i = 0; i < 10; i++) {
      counters.recordCodeSent(entities);
    }
    clock.pin(at(HOUR, 100));
    for (int i = 0; i < 5; i++) {
      counters.recordCodeSent(entities);
    }

    clock.pin(at(HOUR, 0));
    assertThat(counters.read(entities).prefixSent1h()).as("just after the hour: 5 + 10").isEqualTo(15);

    clock.pin(at(HOUR, 1800));
    assertThat(counters.read(entities).prefixSent1h()).as("half way: 5 + 10 * 0.5").isEqualTo(10);

    clock.pin(at(HOUR, 2700));
    assertThat(counters.read(entities).prefixSent1h()).as("three quarters: 5 + floor(10 * 0.25)").isEqualTo(7);

    clock.pin(at(HOUR + 1, 0));
    assertThat(counters.read(entities).prefixSent1h()).as("next hour: only the bucket just ended is left").isEqualTo(5);

    clock.pin(at(HOUR + 2, 0));
    assertThat(counters.read(entities).prefixSent1h()).isZero();
  }

  @Test
  void verifiedCountsAreKeptPerSegmentAndOnlyWhenRecorded() {
    final Entities a = entities(IP, "+8613800130001", "s1");
    final Entities sameSegment = entities(IP, "+8613800139999", "s2");
    final Entities otherSegment = entities(IP, "+8613900130001", "s3");

    counters.recordCodeSent(a);
    counters.recordCodeSent(sameSegment);
    counters.recordCodeSent(otherSegment);
    counters.recordVerified(a);

    final RiskSnapshot snapshot = counters.read(sameSegment);
    assertThat(snapshot.prefixSent1h()).isEqualTo(2);
    assertThat(snapshot.prefixVerified1h()).isEqualTo(1);

    final RiskSnapshot other = counters.read(otherSegment);
    assertThat(other.prefixSent1h()).isEqualTo(1);
    assertThat(other.prefixVerified1h()).isZero();
  }

  // 全局：本小时「本来会放行」数只算当前整点小时

  @Test
  void wouldAllowThisHourOnlyCountsTheCurrentClockHour() {
    final Entities entities = entities(IP, NUMBER, SESSION);

    counters.recordWouldAllow();
    counters.recordWouldAllow();
    counters.recordWouldAllow();
    assertThat(counters.read(entities).wouldAllowThisHour()).isEqualTo(3);

    clock.pin(at(HOUR + 1, 5));
    assertThat(counters.read(entities).wouldAllowThisHour()).isZero();
  }

  @Test
  void cohortCountsUseTheSlidingHour() {
    final Entities entities = entities(IP, NUMBER, SESSION);

    clock.pin(at(HOUR - 1, 10));
    counters.recordCohortSent();
    counters.recordCohortSent();
    counters.recordCohortVerified();
    clock.pin(at(HOUR, 10));
    counters.recordCohortSent();

    clock.pin(at(HOUR, 1800));
    final RiskSnapshot snapshot = counters.read(entities);
    assertThat(snapshot.cohortSent1h()).isEqualTo(1 + 1);
    assertThat(snapshot.cohortVerified1h()).isEqualTo(0);

    clock.pin(at(HOUR, 0));
    assertThat(counters.read(entities).cohortSent1h()).isEqualTo(3);
    assertThat(counters.read(entities).cohortVerified1h()).isEqualTo(1);
  }

  // 会话分组

  @Test
  void cohortOfASessionRoundTripsAndExpires() {
    final Entities entities = entities(IP, NUMBER, SESSION);
    final Entities otherSession = entities(IP, NUMBER, "another-session");

    assertThat(counters.cohort(entities)).isEmpty();

    counters.setCohort(entities, RiskCohort.WOULD_ALLOW);
    counters.setCohort(otherSession, RiskCohort.WOULD_CHALLENGE);

    assertThat(counters.cohort(entities)).contains(RiskCohort.WOULD_ALLOW);
    assertThat(counters.cohort(otherSession)).contains(RiskCohort.WOULD_CHALLENGE);
    assertThat(allKeys()).filteredOn(key -> key.startsWith("regrisk::coh::"))
        .hasSize(2)
        .allSatisfy(key -> assertThat(ttl(key)).isBetween(1L, RegistrationRiskCounters.COHORT_TTL_SECONDS));
  }

  // 解析不了的输入：对应的计数跳过，别的照常

  @Test
  void anUnparseableSourceSkipsTheNetworkCounters() {
    for (final String address : new String[]{null, "", "not-an-ip", "example.com"}) {
      final Entities entities = entities(address, NUMBER, SESSION);

      assertThat(entities.subnet()).isNull();
      assertThat(entities.ip()).isNull();

      counters.recordSession(entities);
    }

    final RiskSnapshot snapshot = counters.read(entities(null, NUMBER, SESSION));
    assertThat(snapshot.subnetSessions24h()).isZero();
    assertThat(snapshot.ipSessions24h()).isZero();
    assertThat(snapshot.numberSessions24h()).isEqualTo(4);
  }

  @Test
  void anUnparseableNumberHasNoSegmentButIsStillCounted() {
    final Entities entities = entities(IP, "not-a-number", SESSION);

    assertThat(entities.prefix()).isNull();

    counters.recordSession(entities);
    counters.recordCodeSent(entities);
    counters.recordVerified(entities);

    final RiskSnapshot snapshot = counters.read(entities);
    assertThat(snapshot.numberSessions24h()).isEqualTo(1);
    assertThat(snapshot.numberCodes24h()).isEqualTo(1);
    assertThat(snapshot.prefixSent1h()).isZero();
    assertThat(snapshot.prefixVerified1h()).isZero();
  }

  // 并发

  @Test
  void concurrentIncrementsAreNotLost() throws Exception {
    final Entities entities = entities(IP, NUMBER, SESSION);
    final ExecutorService executor = Executors.newFixedThreadPool(16);

    try {
      final List<Future<?>> futures = new ArrayList<>();
      for (int i = 0; i < 16; i++) {
        futures.add(executor.submit(() -> {
          for (int j = 0; j < 10; j++) {
            counters.recordSession(entities);
          }
        }));
      }
      for (final Future<?> future : futures) {
        future.get(30, TimeUnit.SECONDS);
      }
    } finally {
      executor.shutdownNow();
    }

    assertThat(counters.read(entities).numberSessions24h()).isEqualTo(160);
    assertThat(counters.read(entities).subnetSessions24h()).isEqualTo(160);
  }

  // Redis 出问题：统一成 RiskUnavailableException，由调用方 fail-open

  @Test
  void redisFailuresBecomeRiskUnavailable() {
    final FaultTolerantRedisClusterClient brokenCluster = mock(FaultTolerantRedisClusterClient.class);
    final RuntimeException failure = new RuntimeException("connection refused");
    when(brokenCluster.withCluster(any())).thenThrow(failure);

    final RegistrationRiskCounters broken = new RegistrationRiskCounters(brokenCluster, "secret", clock);
    final Entities entities = broken.entities(new RiskSignals(IP, NUMBER, "ua", SESSION, false));

    for (final Runnable operation : List.<Runnable>of(
        () -> broken.recordSession(entities),
        () -> broken.recordCodeSent(entities),
        () -> broken.recordVerified(entities),
        broken::recordWouldAllow,
        broken::recordCohortSent,
        broken::recordCohortVerified,
        () -> broken.setCohort(entities, RiskCohort.WOULD_ALLOW),
        () -> broken.cohort(entities),
        () -> broken.read(entities))) {

      assertThatThrownBy(operation::run).isInstanceOf(RiskUnavailableException.class).hasCause(failure);
    }
  }

  @Test
  void aMissingCohortIsEmptyNotAnError() {
    assertThat(counters.cohort(entities(IP, NUMBER, "never-seen"))).isEqualTo(Optional.empty());
  }
}
