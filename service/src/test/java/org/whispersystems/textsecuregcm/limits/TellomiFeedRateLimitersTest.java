/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.limits;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.controllers.TellomiFeedController;
import org.whispersystems.textsecuregcm.redis.ClusterLuaScript;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.util.MockUtils;

/**
 * B-9: the descriptors behind the Tellomi feed limits. This checks the descriptors and their dynamic-config plumbing
 * only; the Redis leaky-bucket script itself is upstream code and needs a Redis cluster (Docker) to run, which was not
 * available when this was written, so it is NOT exercised for these two descriptors.
 */
@SuppressWarnings("unchecked")
class TellomiFeedRateLimitersTest {

  private final DynamicConfiguration configuration = mock(DynamicConfiguration.class);

  private final DynamicConfigurationManager<DynamicConfiguration> dynamicConfig =
      MockUtils.buildMock(DynamicConfigurationManager.class, cfg -> when(cfg.getConfiguration()).thenReturn(configuration));

  private RateLimiters rateLimiters() {
    return new RateLimiters(dynamicConfig, mock(ClusterLuaScript.class), mock(FaultTolerantRedisClusterClient.class),
        mock(ScheduledExecutorService.class), MockUtils.mutableClock(0));
  }

  @Test
  void gettersUseTheDocumentedDefaults() {
    final RateLimiters rateLimiters = rateLimiters();

    assertThat(rateLimiters.getTellomiFeedFriendAssertionLimiter().config())
        .isEqualTo(new RateLimiterConfig(600, Duration.ofSeconds(6), false));
    assertThat(rateLimiters.getTellomiFeedAudienceListLimiter().config())
        .isEqualTo(new RateLimiterConfig(60, Duration.ofSeconds(20), true));
  }

  @Test
  void idsAreTheDynamicConfigKeys() {
    assertThat(RateLimiters.For.TELLOMI_FEED_FRIEND_ASSERTION.id()).isEqualTo("tellomiFeedFriendAssertion");
    assertThat(RateLimiters.For.TELLOMI_FEED_AUDIENCE_LIST.id()).isEqualTo("tellomiFeedAudienceList");
  }

  @Test
  void friendAssertionBucketCoversAFirstSyncAndTheOracleLimiterFailsClosed() {
    final RateLimiterConfig friend = RateLimiters.For.TELLOMI_FEED_FRIEND_ASSERTION.defaultConfig();

    // A first contact sync reports up to ~500 friends (the audience cap is 500 too); it must fit in one burst.
    assertThat(friend.bucketSize()).isGreaterThanOrEqualTo(TellomiFeedController.MAX_AUDIENCE_MEMBERS);
    // Sustained rate: one permit per 6 s = at most 600 per hour per account.
    assertThat(Duration.ofHours(1).dividedBy(friend.permitRegenerationDuration())).isEqualTo(600);
    // This endpoint's 200 / 404 is an account-existence oracle: if Redis is down, refuse rather than allow.
    assertThat(friend.failOpen()).isFalse();
  }

  @Test
  void dynamicConfigOverridesTheDefaults() {
    final RateLimiterConfig override = new RateLimiterConfig(5, Duration.ofMinutes(1), false);
    final Map<String, RateLimiterConfig> limits = new HashMap<>();
    when(configuration.getLimits()).thenReturn(limits);

    final RateLimiters rateLimiters = rateLimiters();
    final RateLimiter friend = rateLimiters.getTellomiFeedFriendAssertionLimiter();
    final RateLimiter audience = rateLimiters.getTellomiFeedAudienceListLimiter();

    limits.put(RateLimiters.For.TELLOMI_FEED_FRIEND_ASSERTION.id(), override);

    assertThat(friend.config()).isEqualTo(override);
    assertThat(audience.config()).isEqualTo(RateLimiters.For.TELLOMI_FEED_AUDIENCE_LIST.defaultConfig());
  }

  @Test
  void degradedPerIpDescriptorsAreWiderThanThePerAccountOnesAndKeepTheirFailMode() {
    final RateLimiters rateLimiters = rateLimiters();

    assertThat(rateLimiters.getTellomiFeedFriendAssertionIpLimiter().config())
        .isEqualTo(new RateLimiterConfig(1200, Duration.ofSeconds(3), false));
    assertThat(rateLimiters.getTellomiFeedAudienceListIpLimiter().config())
        .isEqualTo(new RateLimiterConfig(120, Duration.ofSeconds(10), true));
    assertThat(RateLimiters.For.TELLOMI_FEED_FRIEND_ASSERTION_IP.id()).isEqualTo("tellomiFeedFriendAssertionIp");
    assertThat(RateLimiters.For.TELLOMI_FEED_AUDIENCE_LIST_IP.id()).isEqualTo("tellomiFeedAudienceListIp");

    // Per-IP buckets must hold at least one account's worth (shared NAT) and keep the fail mode of the per-account one.
    final RateLimiterConfig friendIp = RateLimiters.For.TELLOMI_FEED_FRIEND_ASSERTION_IP.defaultConfig();
    final RateLimiterConfig friend = RateLimiters.For.TELLOMI_FEED_FRIEND_ASSERTION.defaultConfig();
    assertThat(friendIp.bucketSize()).isGreaterThan(friend.bucketSize());
    assertThat(friendIp.failOpen()).isEqualTo(friend.failOpen());
    final RateLimiterConfig audienceIp = RateLimiters.For.TELLOMI_FEED_AUDIENCE_LIST_IP.defaultConfig();
    final RateLimiterConfig audience = RateLimiters.For.TELLOMI_FEED_AUDIENCE_LIST.defaultConfig();
    assertThat(audienceIp.bucketSize()).isGreaterThan(audience.bucketSize());
    assertThat(audienceIp.failOpen()).isEqualTo(audience.failOpen());
  }

  @Test
  void authLimiterHasItsDocumentedDefaultsAndFailsOpen() {
    final RateLimiterConfig auth = rateLimiters().getTellomiFeedAuthLimiter().config();

    assertThat(auth).isEqualTo(new RateLimiterConfig(60, Duration.ofMinutes(1), true));
    assertThat(RateLimiters.For.TELLOMI_FEED_AUTH.id()).isEqualTo("tellomiFeedAuth");
    // sustained rate: one permit per minute = 60 credentials an hour per account; clients fetch about one an hour
    assertThat(Duration.ofHours(1).dividedBy(auth.permitRegenerationDuration())).isEqualTo(60);
    // a cheap HMAC with no account-existence oracle: a dead limiter store must not stop everyone from getting credentials
    assertThat(auth.failOpen()).isTrue();
  }

  @Test
  void authLimiterIsConfigurableAtRuntimeAndIndependentOfTheOtherFeedLimiters() {
    final RateLimiterConfig override = new RateLimiterConfig(3, Duration.ofMinutes(10), true);
    final Map<String, RateLimiterConfig> limits = new HashMap<>();
    when(configuration.getLimits()).thenReturn(limits);

    final RateLimiters rateLimiters = rateLimiters();
    final RateLimiter auth = rateLimiters.getTellomiFeedAuthLimiter();
    limits.put(RateLimiters.For.TELLOMI_FEED_AUTH.id(), override);

    assertThat(auth.config()).isEqualTo(override);
    assertThat(rateLimiters.getTellomiFeedFriendAssertionLimiter().config())
        .isEqualTo(RateLimiters.For.TELLOMI_FEED_FRIEND_ASSERTION.defaultConfig());
    assertThat(rateLimiters.getTellomiFeedAudienceListLimiter().config())
        .isEqualTo(RateLimiters.For.TELLOMI_FEED_AUDIENCE_LIST.defaultConfig());
  }
}
