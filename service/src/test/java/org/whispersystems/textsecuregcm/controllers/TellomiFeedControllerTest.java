/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
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

  private static final ResourceExtension resources = ResourceExtension.builder()
      .addProvider(AuthHelper.getAuthFilter())
      .addProvider(new TestRemoteAddressFilterProvider("1.2.3.4"))
      .addProvider(new AuthValueFactoryProvider.Binder<>(AuthenticatedDevice.class))
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new TellomiFeedController(accountsManager, TOKENS, List.of("tellomi.cn"), () -> asnInfoProvider,
          Clock.fixed(NOW, ZoneOffset.UTC)))
      .build();

  @BeforeEach
  void setUp() {
    reset(accountsManager, asnInfoProvider, account);
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
}
