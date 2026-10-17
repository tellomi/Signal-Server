/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.IntStream;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.asn.AsnInfo;
import org.whispersystems.textsecuregcm.asn.AsnInfoProvider;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.TellomiFeedTokens;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.tests.util.AuthHelper;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestRemoteAddressFilterProvider;

@ExtendWith(DropwizardExtensionsSupport.class)
class TellomiFeedControllerTest {

  private static final byte[] SIGNING_KEY = "tellomi-feed-signing-key-for-tests".getBytes(StandardCharsets.UTF_8);
  private static final byte[] PSEUDONYM_KEY = "tellomi-feed-pseudonym-key-for-test".getBytes(StandardCharsets.UTF_8);
  private static final Instant NOW = Instant.parse("2026-10-13T12:00:00Z");
  private static final ObjectMapper MAPPER = new ObjectMapper();
  private static final TellomiFeedTokens TOKENS = new TellomiFeedTokens(SIGNING_KEY, PSEUDONYM_KEY);

  private static final AccountsManager accountsManager = mock(AccountsManager.class);
  private static final AsnInfoProvider asnInfoProvider = mock(AsnInfoProvider.class);
  private static final Account account = mock(Account.class);
  private static final RateLimiters rateLimiters = mock(RateLimiters.class);
  private static final RateLimiter friendLimiter = mock(RateLimiter.class);
  private static final RateLimiter audienceLimiter = mock(RateLimiter.class);
  private static final RateLimiter authLimiter = mock(RateLimiter.class);

  private static final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new TestRemoteAddressFilterProvider("1.2.3.4"))
      .addProvider(new RateLimitExceededExceptionMapper())
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new TellomiFeedController(accountsManager, rateLimiters, TOKENS, List.of("tellomi.cn"), () -> asnInfoProvider,
          Clock.fixed(NOW, ZoneOffset.UTC)))
      .build();

  /// A clock with sub-second precision, as `Clock.systemUTC()` has in production.
  private static final Instant NOW_WITH_NANOS = NOW.plusNanos(654_809_212L);

  private static final ResourceExtension resourcesWithNanos = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new TestRemoteAddressFilterProvider("1.2.3.4"))
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new TellomiFeedController(accountsManager, rateLimiters, TOKENS, List.of("tellomi.cn"), () -> asnInfoProvider,
          Clock.fixed(NOW_WITH_NANOS, ZoneOffset.UTC)))
      .build();

  @BeforeEach
  void setUp() {
    reset(accountsManager, asnInfoProvider, account, rateLimiters, friendLimiter, audienceLimiter, authLimiter);
    when(rateLimiters.getTellomiFeedFriendAssertionLimiter()).thenReturn(friendLimiter);
    when(rateLimiters.getTellomiFeedAudienceListLimiter()).thenReturn(audienceLimiter);
    when(rateLimiters.getTellomiFeedAuthLimiter()).thenReturn(authLimiter);
    when(account.getNumber()).thenReturn(Optional.of("+14150000000"));
    when(accountsManager.getByAccountIdentifier(AuthHelper.VALID_UUID)).thenReturn(Optional.of(account));
    when(asnInfoProvider.lookup(any())).thenReturn(Optional.empty());
  }

  private static Invocation.Builder request(final String path) {
    return resources.getJerseyTest().target(path).request()
        .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD));
  }

  private static JsonNode claims(final String jwt) throws Exception {
    final String[] parts = jwt.split("\\.");
    assertThat(parts).hasSize(3);
    assertThat(new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8))
        .isEqualTo("{\"alg\":\"HS256\",\"typ\":\"JWT\"}");
    return MAPPER.readTree(Base64.getUrlDecoder().decode(parts[1]));
  }

  private static String sub(final UUID aci) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(TOKENS.pseudonym(aci));
  }

  @Test
  void credentialGlobal() throws Exception {
    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/auth").get(String.class));

    assertThat(body.get("region").asText()).isEqualTo("global");
    assertThat(body.get("expires_at").asText()).isEqualTo("2026-10-13T13:00:00Z");
    final JsonNode claims = claims(body.get("token").asText());
    assertThat(claims.size()).isEqualTo(3);
    assertThat(claims.get("sub").asText()).isEqualTo(sub(AuthHelper.VALID_UUID));
    assertThat(claims.get("rgn").asText()).isEqualTo("global");
    assertThat(claims.get("exp").asLong()).isEqualTo(NOW.plusSeconds(3600).getEpochSecond());
  }

  @Test
  void expiresAtIsWholeSecondsAndMatchesExp() throws Exception {
    final JsonNode body = MAPPER.readTree(resourcesWithNanos.getJerseyTest().target("/v1/tellomi/feed/auth").request()
        .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_UUID, AuthHelper.VALID_PASSWORD))
        .get(String.class));

    // the contract's example shape: no fractional seconds
    assertThat(body.get("expires_at").asText()).isEqualTo("2026-10-13T13:00:00Z");
    // and it names the same instant as the token's exp
    assertThat(Instant.parse(body.get("expires_at").asText()).getEpochSecond())
        .isEqualTo(claims(body.get("token").asText()).get("exp").asLong());
  }

  @Test
  void credentialCnByNumber() throws Exception {
    when(account.getNumber()).thenReturn(Optional.of("+8613800138000"));
    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/auth").get(String.class));
    assertThat(body.get("region").asText()).isEqualTo("cn");
    assertThat(claims(body.get("token").asText()).get("rgn").asText()).isEqualTo("cn");
  }

  @ParameterizedTest
  @ValueSource(strings = {"chat.tellomi.cn", "chat.tellomi.cn:443", "CHAT.TELLOMI.CN."})
  void credentialCnByHost(final String host) throws Exception {
    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/auth")
        .header("X-Forwarded-Host", host).get(String.class));
    assertThat(body.get("region").asText()).isEqualTo("cn");
  }

  @Test
  void credentialHostSuffixMustBeWholeLabel() throws Exception {
    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/auth")
        .header("X-Forwarded-Host", "chat.nottellomi.cn").get(String.class));
    assertThat(body.get("region").asText()).isEqualTo("global");
  }

  @Test
  void credentialCnByAddress() throws Exception {
    when(asnInfoProvider.lookup("1.2.3.4")).thenReturn(Optional.of(new AsnInfo(4134, "CN")));
    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/auth").get(String.class));
    assertThat(body.get("region").asText()).isEqualTo("cn");
  }

  @Test
  void credentialNumberless() throws Exception {
    when(account.getNumber()).thenReturn(Optional.empty());
    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/auth").get(String.class));
    assertThat(body.get("region").asText()).isEqualTo("global");
  }

  @Test
  void credentialRequiresAuth() {
    try (final Response response = resources.getJerseyTest().target("/v1/tellomi/feed/auth").request().get()) {
      assertThat(response.getStatus()).isEqualTo(401);
    }
  }

  @Test
  void addFriend() throws Exception {
    final UUID peer = UUID.randomUUID();
    when(accountsManager.getByAccountIdentifier(peer)).thenReturn(Optional.of(mock(Account.class)));

    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", peer.toString())), String.class));

    final JsonNode claims = claims(body.get("assertion").asText());
    assertThat(claims.get("typ").asText()).isEqualTo("tellomi-feed-friend");
    assertThat(claims.get("a").asText()).isEqualTo(sub(AuthHelper.VALID_UUID));
    assertThat(claims.get("b").asText()).isEqualTo(sub(peer));
    assertThat(claims.get("op").asText()).isEqualTo("add");
    assertThat(claims.get("exp").asLong()).isEqualTo(NOW.plusSeconds(300).getEpochSecond());
    assertThat(claims.has("owner")).isFalse();
  }

  @Test
  void addFriendUnknownPeer() {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", UUID.randomUUID().toString())))) {
      assertThat(response.getStatus()).isEqualTo(404);
    }
  }

  /// The 404 of a missing account carries a marker so a client can tell it from the 404 of a server that does not
  /// have the route at all (no `tellomiFeed:` config): `Content-Type: application/json`, body exactly
  /// `{"error":"account_not_found"}`. Spec: draft-workflows/FRIEND-ASSERTION-404-MARKER.md.
  @Test
  void addFriendUnknownPeerCarriesTheAccountNotFoundMarker() throws Exception {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", UUID.randomUUID().toString())))) {
      assertThat(response.getStatus()).isEqualTo(404);
      assertThat(response.getMediaType().getType()).isEqualTo("application");
      assertThat(response.getMediaType().getSubtype()).isEqualTo("json");
      final JsonNode body = MAPPER.readTree(response.readEntity(String.class));
      assertThat(body.size()).isEqualTo(1);
      assertThat(body.get("error").asText()).isEqualTo("account_not_found");
    }
  }

  /// Control: the marker is only for the missing account. Other statuses stay as they were (and have no marker).
  @Test
  void otherFriendAssertionStatusesDoNotCarryTheMarker() {
    try (final Response bad = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", "not-a-uuid")))) {
      assertThat(bad.getStatus()).isEqualTo(400);
      assertThat(bad.readEntity(String.class)).doesNotContain("account_not_found");
    }
    final UUID peer = UUID.randomUUID();
    when(accountsManager.getByAccountIdentifier(peer)).thenReturn(Optional.of(mock(Account.class)));
    try (final Response ok = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", peer.toString())))) {
      assertThat(ok.getStatus()).isEqualTo(200);
      assertThat(ok.readEntity(String.class)).doesNotContain("account_not_found");
    }
  }

  /// Same question for the audience-list route: it never looks accounts up, so it never answers 404 itself. An
  /// ACI that has no account is signed like any other, which means a 404 from that route can only mean "no route"
  /// and needs no marker.
  @Test
  void audienceListNeverAnswersNotFoundForAnUnknownAccount() {
    when(accountsManager.getByAccountIdentifier(any(UUID.class))).thenReturn(Optional.empty());
    when(accountsManager.getByAccountIdentifier(AuthHelper.VALID_UUID)).thenReturn(Optional.of(account));
    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "include", "peer_acis", List.of(UUID.randomUUID().toString()))))) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
  }

  @ParameterizedTest
  @ValueSource(strings = {"not-a-uuid", "1-1-1-1-1", ""})
  void addFriendBadPeer(final String peer) {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", peer)))) {
      assertThat(response.getStatus()).isIn(400, 422);
    }
  }

  @Test
  void addFriendSelf() {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", AuthHelper.VALID_UUID.toString())))) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
  }

  @Test
  void removeFriendWorksForDeletedPeer() throws Exception {
    final UUID peer = UUID.randomUUID();
    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/friend-assertions/" + peer)
        .delete(String.class));

    final JsonNode claims = claims(body.get("assertion").asText());
    assertThat(claims.get("op").asText()).isEqualTo("remove");
    assertThat(claims.get("b").asText()).isEqualTo(sub(peer));
  }

  @Test
  void audienceList() throws Exception {
    final UUID b = UUID.randomUUID();
    final UUID c = UUID.randomUUID();
    final JsonNode body = MAPPER.readTree(request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "exclude",
            "peer_acis", List.of(b.toString(), c.toString(), b.toString(), AuthHelper.VALID_UUID.toString()))),
            String.class));

    final JsonNode claims = claims(body.get("audience_token").asText());
    assertThat(claims.get("typ").asText()).isEqualTo("tellomi-feed-audience");
    assertThat(claims.get("owner").asText()).isEqualTo(sub(AuthHelper.VALID_UUID));
    assertThat(claims.get("kind").asText()).isEqualTo("exclude");
    assertThat(MAPPER.convertValue(claims.get("members"), List.class)).containsExactly(sub(b), sub(c));
    assertThat(claims.get("exp").asLong()).isEqualTo(NOW.plusSeconds(600).getEpochSecond());
    assertThat(claims.has("a")).isFalse();
  }

  @Test
  void audienceListLimits() {
    final List<String> tooMany = new ArrayList<>();
    IntStream.range(0, TellomiFeedController.MAX_AUDIENCE_MEMBERS + 1)
        .forEach(i -> tooMany.add(UUID.randomUUID().toString()));

    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "include", "peer_acis", tooMany)))) {
      assertThat(response.getStatus()).isEqualTo(422);
    }
    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "include", "peer_acis", List.of())))) {
      assertThat(response.getStatus()).isEqualTo(422);
    }
    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "everyone", "peer_acis", List.of(UUID.randomUUID().toString()))))) {
      assertThat(response.getStatus()).isEqualTo(422);
    }
    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "include", "peer_acis", List.of(AuthHelper.VALID_UUID.toString()))))) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
  }

  // ---- B-9: rate limiting of friend assertions and audience lists ----

  @Test
  void addFriendSpendsOnePermitKeyedByCallerAci() throws Exception {
    final UUID peer = UUID.randomUUID();
    when(accountsManager.getByAccountIdentifier(peer)).thenReturn(Optional.of(mock(Account.class)));

    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", peer.toString())))) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verify(friendLimiter, times(1)).validate(AuthHelper.VALID_UUID);
    verifyNoInteractions(audienceLimiter);
  }

  @Test
  void addFriendRateLimitedIsTooManyRequestsAndLeaksNothing() throws Exception {
    doThrow(new RateLimitExceededException(Duration.ofSeconds(42))).when(friendLimiter).validate(any(UUID.class));
    final UUID existing = UUID.randomUUID();
    when(accountsManager.getByAccountIdentifier(existing)).thenReturn(Optional.of(mock(Account.class)));

    // An existing and a non-existing peer must be indistinguishable once the limit is hit
    // (the whole point of the limit: the 200 / 404 difference is an account-existence oracle).
    for (final UUID peer : List.of(existing, UUID.randomUUID())) {
      try (final Response response = request("/v1/tellomi/feed/friend-assertions")
          .post(Entity.json(Map.of("peer_aci", peer.toString())))) {
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeaderString("Retry-After")).isEqualTo("42");
        assertThat(response.hasEntity() ? response.readEntity(String.class) : "").doesNotContain("assertion");
      }
    }
    // No account lookup happened for either: the limiter runs before the existence check.
    verifyNoInteractions(accountsManager);
  }

  @ParameterizedTest
  @ValueSource(strings = {"not-a-uuid", "1-1-1-1-1"})
  void malformedFriendRequestsStillCostAPermit(final String peer) throws Exception {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", peer)))) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
    verify(friendLimiter, times(1)).validate(AuthHelper.VALID_UUID);
  }

  @Test
  void selfFriendRequestStillCostsAPermit() throws Exception {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", AuthHelper.VALID_UUID.toString())))) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
    verify(friendLimiter, times(1)).validate(AuthHelper.VALID_UUID);
  }

  @Test
  void removeFriendIsNotRateLimited() throws Exception {
    // No account lookup, so no existence oracle: deliberately outside the limiter (decision recorded in the B-9 notes).
    try (final Response response = request("/v1/tellomi/feed/friend-assertions/" + UUID.randomUUID()).delete()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verifyNoInteractions(friendLimiter, audienceLimiter);
  }

  @Test
  void audienceListSpendsOnePermitKeyedByCallerAci() throws Exception {
    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "include", "peer_acis", List.of(UUID.randomUUID().toString()))))) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verify(audienceLimiter, times(1)).validate(AuthHelper.VALID_UUID);
    verifyNoInteractions(friendLimiter);
  }

  @Test
  void audienceListRateLimitedIsTooManyRequestsWithoutASignature() throws Exception {
    doThrow(new RateLimitExceededException(Duration.ofSeconds(7))).when(audienceLimiter).validate(any(UUID.class));

    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "include", "peer_acis", List.of(UUID.randomUUID().toString()))))) {
      assertThat(response.getStatus()).isEqualTo(429);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("7");
      assertThat(response.hasEntity() ? response.readEntity(String.class) : "").doesNotContain("audience_token");
    }
  }

  @Test
  void audienceListBodyValidationRunsBeforeTheLimiter() throws Exception {
    // Bean validation (422) is done by Jersey before the method body, so oversized / empty lists do not spend a permit.
    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "everyone", "peer_acis", List.of(UUID.randomUUID().toString()))))) {
      assertThat(response.getStatus()).isEqualTo(422);
    }
    verify(audienceLimiter, never()).validate(anyString());
    verify(audienceLimiter, never()).validate(any(UUID.class));
  }

  // ---- server-feed-audit S-3: the limiter's backing store (Redis) is down ----
  // A limiter with failOpen = false rethrows whatever the store threw (LeakyBucketRateLimiter#validate), a plain
  // runtime exception. That used to surface as an anonymous 500; it is a dependency outage, so say 503 with a
  // Retry-After the clients can read, still fail closed (no signature) and still without an existence lookup.

  @Test
  void addFriendLimiterStoreDownIsServiceUnavailableAndFailsClosed() throws Exception {
    doThrow(new RuntimeException("redis down")).when(friendLimiter).validate(any(UUID.class));
    final UUID existing = UUID.randomUUID();
    when(accountsManager.getByAccountIdentifier(existing)).thenReturn(Optional.of(mock(Account.class)));

    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", existing.toString())))) {
      assertThat(response.getStatus()).isEqualTo(503);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("30");
      assertThat(response.hasEntity() ? response.readEntity(String.class) : "").doesNotContain("assertion");
    }
    verifyNoInteractions(accountsManager);
  }

  @Test
  void audienceListLimiterStoreDownIsServiceUnavailableWithoutASignature() throws Exception {
    doThrow(new RuntimeException("redis down")).when(audienceLimiter).validate(any(UUID.class));

    try (final Response response = request("/v1/tellomi/feed/audience-lists")
        .post(Entity.json(Map.of("kind", "include", "peer_acis", List.of(UUID.randomUUID().toString()))))) {
      assertThat(response.getStatus()).isEqualTo(503);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("30");
      assertThat(response.hasEntity() ? response.readEntity(String.class) : "").doesNotContain("audience_token");
    }
  }

  @Test
  void rateLimitedStaysTooManyRequestsWhenTheStoreErrorHandlingIsInPlace() throws Exception {
    // Control: a real "limit hit" must not be turned into 503 by the store-down handling.
    doThrow(new RateLimitExceededException(Duration.ofSeconds(9))).when(friendLimiter).validate(any(UUID.class));

    try (final Response response = request("/v1/tellomi/feed/friend-assertions")
        .post(Entity.json(Map.of("peer_aci", UUID.randomUUID().toString())))) {
      assertThat(response.getStatus()).isEqualTo(429);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("9");
    }
  }

  // ---- audit SF-4: GET /auth is limited per account (its own limiter; the other feed limiters are not involved) ----

  @Test
  void credentialIsLimitedPerCallingAccountByItsOwnLimiter() throws Exception {
    try (final Response response = request("/v1/tellomi/feed/auth").get()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verify(authLimiter).validate(AuthHelper.VALID_UUID);
    verifyNoInteractions(friendLimiter, audienceLimiter);
  }

  @Test
  void credentialOverTheLimitIsTooManyRequestsWithRetryAfterAndNoToken() throws Exception {
    doThrow(new RateLimitExceededException(Duration.ofSeconds(42))).when(authLimiter).validate(any(UUID.class));

    try (final Response response = request("/v1/tellomi/feed/auth").get()) {
      assertThat(response.getStatus()).isEqualTo(429);
      // whole seconds, what Android / iOS read for `auth_throttled`
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("42");
      assertThat(response.hasEntity() ? response.readEntity(String.class) : "").doesNotContain("token");
    }
    // limited before anything else: no account lookup, no signing work
    verifyNoInteractions(accountsManager);
    verifyNoInteractions(friendLimiter, audienceLimiter);
  }

  @Test
  void credentialRetryAfterIsAnIntegerNumberOfSeconds() throws Exception {
    doThrow(new RateLimitExceededException(Duration.ofMillis(5400))).when(authLimiter).validate(any(UUID.class));

    try (final Response response = request("/v1/tellomi/feed/auth").get()) {
      assertThat(response.getStatus()).isEqualTo(429);
      assertThat(response.getHeaderString("Retry-After")).matches("[0-9]+");
    }
  }

  @Test
  void credentialLimiterStoreDownIsServiceUnavailableWithoutAToken() throws Exception {
    // the production limiter is failOpen = true, which swallows a store error and lets the request through (see
    // TellomiFeedRateLimitersTest); anything that still escapes is a dependency outage: 503 + Retry-After, not a bare 500
    doThrow(new RuntimeException("redis down")).when(authLimiter).validate(any(UUID.class));

    try (final Response response = request("/v1/tellomi/feed/auth").get()) {
      assertThat(response.getStatus()).isEqualTo(503);
      assertThat(response.getHeaderString("Retry-After")).isEqualTo("30");
      assertThat(response.hasEntity() ? response.readEntity(String.class) : "").doesNotContain("token");
    }
  }

  @Test
  void aDifferentAccountsLimitDoesNotAffectThisOne() throws Exception {
    // the limiter is keyed by the caller's ACI: only calls for the other account are refused
    final UUID other = UUID.randomUUID();
    doThrow(new RateLimitExceededException(Duration.ofSeconds(5))).when(authLimiter).validate(other);

    try (final Response response = request("/v1/tellomi/feed/auth").get()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verify(authLimiter).validate(AuthHelper.VALID_UUID);
    verify(authLimiter, never()).validate(other);
  }

  @Test
  void otherRoutesAreStillNotCoveredByTheAuthLimiter() throws Exception {
    try (final Response response = request("/v1/tellomi/feed/friend-assertions/" + UUID.randomUUID()).delete()) {
      assertThat(response.getStatus()).isEqualTo(200);
    }
    verifyNoInteractions(authLimiter);
  }
}
