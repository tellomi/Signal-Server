/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;
import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.zip.GZIPOutputStream;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.asn.AsnInfoProvider;
import org.whispersystems.textsecuregcm.asn.AsnInfoProviderImpl;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.TellomiFeedTokens;
import org.whispersystems.textsecuregcm.filters.RemoteAddressFilter;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestRemoteAddressFilterProvider;

/**
 * B-9 degraded policy: while the ASN table is empty (not loaded / failed to load) the friend-assertion and
 * audience-list endpoints are limited per account AND per source address; with a loaded table only the per-account
 * limiter applies (unchanged behaviour). The counter and the WARN stay emitted.
 *
 * The limiters are mocks: the Redis leaky-bucket behind them is not exercised here (no Redis / Docker available).
 */
@ExtendWith(DropwizardExtensionsSupport.class)
class TellomiFeedDegradedLimitTest {

  private static final String IP = "1.2.3.4";
  private static final Instant NOW = Instant.parse("2026-10-13T12:00:00Z");

  private static final AccountsManager accountsManager = mock(AccountsManager.class);
  private static final RateLimiters rateLimiters = mock(RateLimiters.class);
  private static final RateLimiter friendLimiter = mock(RateLimiter.class);
  private static final RateLimiter audienceLimiter = mock(RateLimiter.class);
  private static final RateLimiter authLimiter = mock(RateLimiter.class);
  private static final RateLimiter friendIpLimiter = mock(RateLimiter.class);
  private static final RateLimiter audienceIpLimiter = mock(RateLimiter.class);
  /// Switched per test: AsnInfoProvider.EMPTY (degraded) or a non-empty provider (table loaded).
  private static final AtomicReference<AsnInfoProvider> provider = new AtomicReference<>(AsnInfoProvider.EMPTY);
  private static final AsnInfoProvider LOADED = mock(AsnInfoProvider.class);

  private static TellomiFeedController newController() {
    return new TellomiFeedController(accountsManager, rateLimiters,
        new TellomiFeedTokens("signing-key-for-degraded-tests-000001".getBytes(StandardCharsets.UTF_8),
            "pseudonym-key-for-degraded-tests-0002".getBytes(StandardCharsets.UTF_8)),
        List.of("tellomi.cn"), provider::get, Clock.fixed(NOW, java.time.ZoneOffset.UTC));
  }

  private static final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new TestRemoteAddressFilterProvider(IP))
      .addProvider(new RateLimitExceededExceptionMapper())
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(newController())
      .build();

  private SimpleMeterRegistry registry;

  @BeforeEach
  void setUp() {
    reset(accountsManager, rateLimiters, friendLimiter, audienceLimiter, authLimiter, friendIpLimiter, audienceIpLimiter, LOADED);
    provider.set(AsnInfoProvider.EMPTY);
    when(LOADED.lookup(any())).thenReturn(Optional.empty());
    when(rateLimiters.getTellomiFeedFriendAssertionLimiter()).thenReturn(friendLimiter);
    when(rateLimiters.getTellomiFeedAudienceListLimiter()).thenReturn(audienceLimiter);
    when(rateLimiters.getTellomiFeedAuthLimiter()).thenReturn(authLimiter);
    when(rateLimiters.getTellomiFeedFriendAssertionIpLimiter()).thenReturn(friendIpLimiter);
    when(rateLimiters.getTellomiFeedAudienceListIpLimiter()).thenReturn(audienceIpLimiter);
    when(accountsManager.getByAccountIdentifier(any(UUID.class))).thenReturn(Optional.of(mock(Account.class)));
    registry = new SimpleMeterRegistry();
    Metrics.addRegistry(registry);
  }

  @AfterEach
  void tearDown() {
    Metrics.removeRegistry(registry);
  }

  private static Invocation.Builder request(final String path) {
    return resources.getJerseyTest().target(path).request()
        .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD));
  }

  private static int postFriend() {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", UUID.randomUUID().toString())))) {
      return response.getStatus();
    }
  }

  private static Response postAudience() {
    return request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "include", "peer_acis", List.of(UUID.randomUUID().toString()))));
  }

  private double count(final String name, final String... tags) {
    final var counter = registry.find(name(TellomiFeedController.class, name)).tags(tags).counter();
    return counter == null ? 0 : counter.count();
  }

  // ---- empty table: both layers ----

  @Test
  void emptyTableFriendAssertionAppliesPerIpThenPerAccount() throws Exception {
    assertThat(postFriend()).isEqualTo(200);

    final InOrder order = inOrder(friendIpLimiter, friendLimiter);
    order.verify(friendIpLimiter).validate(IP);
    order.verify(friendLimiter).validate(AuthHelper.VALID_UUID);
    verifyNoInteractions(audienceIpLimiter, audienceLimiter);
  }

  @Test
  void emptyTableAudienceListAppliesPerIpThenPerAccount() throws Exception {
    try (final Response response = postAudience()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }

    final InOrder order = inOrder(audienceIpLimiter, audienceLimiter);
    order.verify(audienceIpLimiter).validate(IP);
    order.verify(audienceLimiter).validate(AuthHelper.VALID_UUID);
    verifyNoInteractions(friendIpLimiter, friendLimiter);
  }

  @Test
  void emptyTableIpLimitExceededIsTooManyRequestsAndSpendsNoAccountPermitOrLookup() throws Exception {
    doThrow(new RateLimitExceededException(Duration.ofSeconds(30))).when(friendIpLimiter).validate(IP);

    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", UUID.randomUUID().toString())))) {
      assertThat(response.getStatus()).isEqualTo(429);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("30");
      assertThat(response.hasEntity() ? response.readEntity(String.class) : "").doesNotContain("assertion");
    }
    verify(friendLimiter, never()).validate(any(UUID.class));
    verify(accountsManager, never()).getByAccountIdentifier(any(UUID.class));

    doThrow(new RateLimitExceededException(Duration.ofSeconds(9))).when(audienceIpLimiter).validate(IP);
    try (final Response response = postAudience()) {
      assertThat(response.getStatus()).isEqualTo(429);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("9");
      assertThat(response.hasEntity() ? response.readEntity(String.class) : "").doesNotContain("audience_token");
    }
    verify(audienceLimiter, never()).validate(any(UUID.class));
  }

  @Test
  void emptyTableAccountLimitStillAppliesWhenTheIpLimitPasses() throws Exception {
    doThrow(new RateLimitExceededException(Duration.ofSeconds(42))).when(friendLimiter).validate(any(UUID.class));

    assertThat(postFriend()).isEqualTo(429);

    verify(friendIpLimiter, times(1)).validate(IP);
    verify(accountsManager, never()).getByAccountIdentifier(any(UUID.class));
  }

  @Test
  void emptyTableBodyValidationStillRunsBeforeAnyLimiter() throws Exception {
    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "everyone", "peer_acis", List.of(UUID.randomUUID().toString()))))) {
      assertThat(response.getStatus()).isEqualTo(422);
    }
    verifyNoInteractions(audienceIpLimiter, audienceLimiter);
  }

  @Test
  void emptyTableDeleteUsesOnlyThePerAccountFriendBucketAndAuthKeepsOnlyItsPerAccountLimit() throws Exception {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions/" + UUID.randomUUID()).delete()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    when(accountsManager.getByAccountIdentifier(AuthHelper.VALID_UUID)).thenReturn(Optional.of(mock(Account.class)));
    try (final Response response = request("/v1/tellomi/feed/auth").get()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    // DELETE shares the per-account tellomiFeedFriendAssertion bucket (no per-IP layer, no account lookup)
    verify(friendLimiter, times(1)).validate(AuthHelper.VALID_UUID);
    verifyNoInteractions(friendIpLimiter, audienceIpLimiter, audienceLimiter);
    // SF-4: /auth has its own per-account limiter and, unlike the two routes above, no extra per-IP layer
    verify(authLimiter, times(1)).validate(AuthHelper.VALID_UUID);
  }

  @Test
  void emptyTableCountersAreEmitted() throws Exception {
    postFriend();
    try (final Response response = postAudience()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    postFriend();

    assertThat(count("asnTableEmpty")).isEqualTo(3);
    assertThat(count("degradedIpLimit", "endpoint", "friendAssertion")).isEqualTo(2);
    assertThat(count("degradedIpLimit", "endpoint", "audienceList")).isEqualTo(1);
  }

  @Test
  void emptyTableWarnsExactlyOnce() throws Exception {
    final Logger logger = (Logger) LoggerFactory.getLogger(TellomiFeedController.class);
    final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    logs.start();
    logger.addAppender(logs);
    try {
      final TellomiFeedController controller = newController();
      final AuthenticatedDevice auth = new AuthenticatedDevice(AuthHelper.VALID_UUID, (byte) 1, NOW);
      final ContainerRequestContext context = requestContext(IP);
      final TellomiFeedController.FriendAssertionRequest body =
          new TellomiFeedController.FriendAssertionRequest(UUID.randomUUID().toString());

      controller.addFriend(auth, body, context);
      controller.addFriend(auth, body, context);

      final List<ILoggingEvent> warnings = logs.list.stream().filter(e -> e.getLevel() == Level.WARN).toList();
      assertThat(warnings).hasSize(1);
      assertThat(warnings.getFirst().getFormattedMessage()).contains("ASN table is empty").contains("per account AND per source address");
    } finally {
      logger.detachAppender(logs);
    }
  }

  @Test
  void emptyTableWithoutARemoteAddressUsesASharedKeyInsteadOfSkippingTheLimiter() throws Exception {
    final TellomiFeedController controller = newController();
    final AuthenticatedDevice auth = new AuthenticatedDevice(AuthHelper.VALID_UUID, (byte) 1, NOW);

    controller.addFriend(auth, new TellomiFeedController.FriendAssertionRequest(UUID.randomUUID().toString()),
        requestContext(null));

    verify(friendIpLimiter).validate("unknown");
    verify(friendLimiter).validate(AuthHelper.VALID_UUID);
  }

  // ---- a table that loaded but has no rows (what Hong Kong's asnTable points at today) ----

  @Test
  void aLoadedButEmptyTableIsDegradedToo() throws Exception {
    final AsnInfoProvider loadedEmpty = AsnInfoProviderImpl.fromTsvGz(new ByteArrayInputStream(emptyGzip()));
    assertThat(loadedEmpty).isNotSameAs(AsnInfoProvider.EMPTY);
    assertThat(loadedEmpty.isEmpty()).isTrue();
    provider.set(loadedEmpty);

    assertThat(postFriend()).isEqualTo(200);

    final InOrder order = inOrder(friendIpLimiter, friendLimiter);
    order.verify(friendIpLimiter).validate(IP);
    order.verify(friendLimiter).validate(AuthHelper.VALID_UUID);
    assertThat(count("degradedIpLimit", "endpoint", "friendAssertion")).isEqualTo(1);
  }

  private static byte[] emptyGzip() throws IOException {
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (final GZIPOutputStream gzip = new GZIPOutputStream(bytes)) {
      gzip.write(new byte[0]);
    }
    return bytes.toByteArray();
  }

  // ---- loaded table: unchanged ----

  @Test
  void loadedTableOnlyTheAccountLimiterApplies() throws Exception {
    provider.set(LOADED);

    assertThat(postFriend()).isEqualTo(200);
    try (final Response response = postAudience()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }

    verify(friendLimiter, times(1)).validate(AuthHelper.VALID_UUID);
    verify(audienceLimiter, times(1)).validate(AuthHelper.VALID_UUID);
    verifyNoInteractions(friendIpLimiter, audienceIpLimiter);
    assertThat(count("asnTableEmpty")).isZero();
    assertThat(count("degradedIpLimit", "endpoint", "friendAssertion")).isZero();
  }

  @Test
  void theIpLayerSwitchesOffWhenTheTableGetsLoaded() throws Exception {
    assertThat(postFriend()).isEqualTo(200);
    verify(friendIpLimiter, times(1)).validate(IP);

    provider.set(LOADED);
    assertThat(postFriend()).isEqualTo(200);

    verify(friendIpLimiter, times(1)).validate(IP);
    verify(friendLimiter, times(2)).validate(AuthHelper.VALID_UUID);
  }

  private static ContainerRequestContext requestContext(final String remoteAddress) {
    final ContainerRequestContext context = mock(ContainerRequestContext.class);
    when(context.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME)).thenReturn(remoteAddress);
    return context;
  }
}
