/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.JsonNode;
import com.google.i18n.phonenumbers.PhoneNumberUtil;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;
import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.stubbing.Answer;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.auth.PhoneVerificationTokenManager;
import org.whispersystems.textsecuregcm.auth.StoredRegistrationLock;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.JsonMappingExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceClient;
import org.whispersystems.textsecuregcm.spam.RegistrationRecoveryChecker;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.AnnotatedTotpKey;
import org.whispersystems.textsecuregcm.storage.PhoneNumberIdentifiers;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.storage.TotpKey;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/// Tellomi（Google Play 删号）：网页自助删号。PhoneVerificationTokenManager 用真的、只 mock 注册服务，
/// 所以「会话未验证 / 号码不符 / 注册服务不可用」走的是和注册接口同一套判定。
@ExtendWith(DropwizardExtensionsSupport.class)
class TellomiAccountDeletionControllerTest {

  private static final String NUMBER = PhoneNumberUtil.getInstance().format(
      PhoneNumberUtil.getInstance().getExampleNumberForType("CN", PhoneNumberUtil.PhoneNumberType.MOBILE),
      PhoneNumberUtil.PhoneNumberFormat.E164);

  private static final String OTHER_NUMBER = PhoneNumberUtil.getInstance().format(
      PhoneNumberUtil.getInstance().getExampleNumber("US"),
      PhoneNumberUtil.PhoneNumberFormat.E164);

  // 0xfb 0xff 0xbf 编成 URL-safe base64 是 "-_-_"（标准 base64 是 "+/+/"），能验出用的是注册接口那种编码
  private static final byte[] SESSION_ID =
      {(byte) 0xfb, (byte) 0xff, (byte) 0xbf, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
  private static final String ENCODED_SESSION_ID = RegistrationServiceSession.encodeSessionId(SESSION_ID);

  private static final UUID ACI = UUID.randomUUID();

  private final AccountsManager accountsManager = mock(AccountsManager.class);
  private final RegistrationServiceClient registrationServiceClient = mock(RegistrationServiceClient.class);
  private final RateLimiters rateLimiters = mock(RateLimiters.class);
  private final RateLimiter registrationLimiter = mock(RateLimiter.class);

  private final ResourceExtension resources = ResourceExtension.builder()
      .addProperty(ServerProperties.UNWRAP_COMPLETION_STAGE_IN_WRITER_ENABLE, Boolean.TRUE)
      .addProvider(new RateLimitExceededExceptionMapper())
      .addProvider(new JsonMappingExceptionMapper())
      .setMapper(SystemMapper.jsonMapper())
      .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
      .addResource(new TellomiAccountDeletionController(accountsManager,
          new PhoneVerificationTokenManager(mock(PhoneNumberIdentifiers.class), registrationServiceClient,
              mock(PhoneNumberRecoveryPasswordsManager.class), mock(RegistrationRecoveryChecker.class)),
          rateLimiters))
      .build();

  @BeforeEach
  void setUp() {
    when(rateLimiters.getRegistrationLimiter()).thenReturn(registrationLimiter);
  }

  @Test
  void deleteWithVerifiedSession() throws Exception {
    givenSession(NUMBER, true);
    givenAccount(NUMBER, noRegistrationLock());

    try (final Response response = post(NUMBER, ENCODED_SESSION_ID)) {
      assertEquals(204, response.getStatus());
    }

    verify(registrationServiceClient).getSession(aryEq(SESSION_ID), any());
    verify(registrationLimiter).validate(NUMBER);
    verify(accountsManager).delete(ACI, AccountsManager.DeletionReason.USER_REQUEST);
    verify(accountsManager).delete(any(UUID.class), any());   // 总共只删了这一次
  }

  @Test
  void deletionLogLineHasNoFullNumber() {
    givenSession(NUMBER, true);
    givenAccount(NUMBER, noRegistrationLock());

    final Logger logger = (Logger) LoggerFactory.getLogger(TellomiAccountDeletionController.class);
    final Level previousLevel = logger.getLevel();
    final ListAppender<ILoggingEvent> logs = new ListAppender<>();
    logs.start();
    logger.addAppender(logs);
    logger.setLevel(Level.INFO);

    try (final Response response = post(NUMBER, ENCODED_SESSION_ID)) {
      assertEquals(204, response.getStatus());
    } finally {
      logger.detachAppender(logs);
      logger.setLevel(previousLevel);
    }

    assertEquals(1, logs.list.size());
    final String line = logs.list.getFirst().getFormattedMessage();
    assertEquals(Level.INFO, logs.list.getFirst().getLevel());
    assertTrue(line.contains(ACI.toString()), line);
    assertTrue(line.contains("+86???" + NUMBER.substring(NUMBER.length() - 2)), line);
    assertFalse(line.contains(NUMBER.substring("+86".length(), NUMBER.length() - 2)), line);
  }

  @ParameterizedTest
  @MethodSource
  void sessionNotAccepted(final Answer<Optional<RegistrationServiceSession>> getSession,
      final int expectedStatus, final String expectedReason) throws Exception {

    when(registrationServiceClient.getSession(any(), any())).thenAnswer(getSession);
    givenAccount(NUMBER, noRegistrationLock());

    try (final Response response = post(NUMBER, ENCODED_SESSION_ID)) {
      assertEquals(expectedStatus, response.getStatus());
      assertEquals(Map.of("reason", expectedReason), reason(response));
    }

    verify(accountsManager, never()).delete(any(), any());
    verify(accountsManager, never()).getByE164(any());
    verifyNoInteractions(registrationLimiter);
  }

  private static Stream<Arguments> sessionNotAccepted() {
    return Stream.of(
        Arguments.argumentSet("unverified session",
            (Answer<?>) _ -> Optional.of(session(NUMBER, false)), 401, "session_not_verified"),
        Arguments.argumentSet("unknown or expired session",
            (Answer<?>) _ -> Optional.empty(), 401, "session_not_verified"),
        Arguments.argumentSet("session verified for another number",
            (Answer<?>) _ -> Optional.of(session(OTHER_NUMBER, true)), 400, "invalid_session"),
        Arguments.argumentSet("session ID rejected by the registration service",
            (Answer<?>) _ -> { throw new StatusRuntimeException(Status.INVALID_ARGUMENT); }, 400, "invalid_session"),
        Arguments.argumentSet("registration service unavailable",
            (Answer<?>) _ -> { throw new StatusRuntimeException(Status.UNAVAILABLE); }, 503, "unavailable"));
  }

  @Test
  void notRegistered() throws Exception {
    givenSession(NUMBER, true);

    try (final Response response = post(NUMBER, ENCODED_SESSION_ID)) {
      assertEquals(404, response.getStatus());
      assertEquals(Map.of("reason", "not_registered"), reason(response));
    }

    verify(accountsManager, never()).delete(any(), any());
  }

  @Test
  void registrationLockRequired() throws Exception {
    givenSession(NUMBER, true);
    givenAccount(NUMBER, registrationLockLastSeen(Duration.ofDays(1)));

    try (final Response response = post(NUMBER, ENCODED_SESSION_ID)) {
      assertEquals(423, response.getStatus());

      final JsonNode body = SystemMapper.jsonMapper().readTree(response.readEntity(String.class));
      assertEquals("registration_lock", body.get("reason").asText());
      final long timeRemaining = body.get("timeRemaining").asLong();
      assertTrue(timeRemaining > Duration.ofDays(5).toMillis() && timeRemaining <= Duration.ofDays(6).toMillis(),
          "timeRemaining " + timeRemaining);
    }

    // 只查了账号：没删，也没像 verifyRegistrationLock 那样去冻结凭据（那要 update）
    verify(accountsManager).getByE164(NUMBER);
    verifyNoMoreInteractions(accountsManager);
  }

  @Test
  void registrationLockExpired() throws Exception {
    givenSession(NUMBER, true);
    givenAccount(NUMBER, registrationLockLastSeen(Duration.ofDays(8)));

    try (final Response response = post(NUMBER, ENCODED_SESSION_ID)) {
      assertEquals(204, response.getStatus());
    }

    verify(accountsManager).delete(ACI, AccountsManager.DeletionReason.USER_REQUEST);
  }

  @Test
  void secondFactor() throws Exception {
    givenSession(NUMBER, true);
    final Account account = givenAccount(NUMBER, noRegistrationLock());
    when(account.getMfaKeys()).thenReturn(Map.of((byte) 1, new AnnotatedTotpKey(mock(TotpKey.class), new byte[0])));

    try (final Response response = post(NUMBER, ENCODED_SESSION_ID)) {
      assertEquals(423, response.getStatus());
      assertEquals(Map.of("reason", "mfa"), reason(response));
    }

    verify(accountsManager, never()).delete(any(), any());
  }

  @Test
  void rateLimited() throws Exception {
    givenSession(NUMBER, true);
    givenAccount(NUMBER, noRegistrationLock());
    doThrow(new RateLimitExceededException(Duration.ofSeconds(30))).when(registrationLimiter).validate(NUMBER);

    try (final Response response = post(NUMBER, ENCODED_SESSION_ID)) {
      assertEquals(429, response.getStatus());
      assertEquals("30", response.getHeaderString(HttpHeaders.RETRY_AFTER));
    }

    verifyNoInteractions(accountsManager);
  }

  @Test
  void accountRegisteredUnderAlternateNumberForm() throws Exception {
    final String newFormatBeninNumber = PhoneNumberUtil.getInstance()
        .format(PhoneNumberUtil.getInstance().getExampleNumber("BJ"), PhoneNumberUtil.PhoneNumberFormat.E164);
    final String oldFormatBeninNumber = newFormatBeninNumber.replaceFirst("01", "");

    givenSession(newFormatBeninNumber, true);
    givenAccount(oldFormatBeninNumber, noRegistrationLock());

    try (final Response response = post(newFormatBeninNumber, ENCODED_SESSION_ID)) {
      assertEquals(204, response.getStatus());
    }

    verify(accountsManager).delete(ACI, AccountsManager.DeletionReason.USER_REQUEST);
  }

  @ParameterizedTest
  @MethodSource
  void malformedRequest(final String json, final int expectedStatus) {
    givenSession(NUMBER, true);
    givenAccount(NUMBER, noRegistrationLock());

    try (final Response response = resources.getJerseyTest()
        .target("/v1/tellomi/account-deletion")
        .request()
        .post(Entity.entity(json, MediaType.APPLICATION_JSON_TYPE))) {

      assertEquals(expectedStatus, response.getStatus());
    }

    verifyNoInteractions(registrationServiceClient, registrationLimiter);
    verify(accountsManager, never()).delete(any(), any());
  }

  private static Stream<Arguments> malformedRequest() {
    return Stream.of(
        Arguments.argumentSet("not JSON", "{", 400),
        Arguments.argumentSet("no body", "", 422),
        Arguments.argumentSet("no number", json(null, ENCODED_SESSION_ID), 422),
        Arguments.argumentSet("number not e164", json("not-a-number", ENCODED_SESSION_ID), 422),
        Arguments.argumentSet("number without +", json(NUMBER.substring(1), ENCODED_SESSION_ID), 422),
        Arguments.argumentSet("no session ID", json(NUMBER, null), 422),
        Arguments.argumentSet("blank session ID", json(NUMBER, " "), 422),
        Arguments.argumentSet("session ID not base64", json(NUMBER, "not base64!"), 422),
        Arguments.argumentSet("session ID in standard (not URL-safe) base64",
            json(NUMBER, ENCODED_SESSION_ID.replace('-', '+').replace('_', '/')), 422),
        Arguments.argumentSet("session ID not a string",
            "{\"number\":\"" + NUMBER + "\",\"sessionId\":[\"" + ENCODED_SESSION_ID + "\"]}", 422));
  }

  private Response post(final String number, final String sessionId) {
    return resources.getJerseyTest()
        .target("/v1/tellomi/account-deletion")
        .request()
        .post(Entity.json(new TellomiAccountDeletionController.AccountDeletionRequest(number, sessionId)));
  }

  private void givenSession(final String sessionNumber, final boolean verified) {
    when(registrationServiceClient.getSession(any(), any())).thenReturn(Optional.of(session(sessionNumber, verified)));
  }

  private Account givenAccount(final String number, final StoredRegistrationLock registrationLock) {
    final Account account = mock(Account.class);
    when(account.getAccountIdentifier()).thenReturn(ACI);
    when(account.getNumber()).thenReturn(Optional.of(number));
    when(account.getRegistrationLock()).thenReturn(registrationLock);
    when(accountsManager.getByE164(number)).thenReturn(Optional.of(account));
    return account;
  }

  private static RegistrationServiceSession session(final String number, final boolean verified) {
    return new RegistrationServiceSession(SESSION_ID, number, verified, null, null, null, 0L);
  }

  private static StoredRegistrationLock noRegistrationLock() {
    return new StoredRegistrationLock(Optional.empty(), Optional.empty(), Instant.now());
  }

  private static StoredRegistrationLock registrationLockLastSeen(final Duration sinceLastSeen) {
    return new StoredRegistrationLock(Optional.of("hash"), Optional.of("salt"), Instant.now().minus(sinceLastSeen));
  }

  private static Map<?, ?> reason(final Response response) throws Exception {
    return SystemMapper.jsonMapper().readValue(response.readEntity(String.class), Map.class);
  }

  private static String json(final String number, final String sessionId) {
    final Map<String, String> fields = new HashMap<>();
    if (number != null) {
      fields.put("number", number);
    }
    if (sessionId != null) {
      fields.put("sessionId", sessionId);
    }
    try {
      return SystemMapper.jsonMapper().writeValueAsString(fields);
    } catch (final Exception e) {
      throw new AssertionError(e);
    }
  }
}
