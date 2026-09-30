/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.dropwizard.testing.junit5.ResourceExtension;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import org.glassfish.jersey.server.ServerProperties;
import org.glassfish.jersey.test.grizzly.GrizzlyWebTestContainerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.whispersystems.textsecuregcm.captcha.RegistrationCaptchaManager;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicCarrierDataLookupConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicRegistrationConfiguration;
import org.whispersystems.textsecuregcm.entities.RegistrationServiceSession;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.mappers.ImpossiblePhoneNumberExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.NonNormalizedPhoneNumberExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.ObsoletePhoneNumberFormatExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.RateLimitExceededExceptionMapper;
import org.whispersystems.textsecuregcm.mappers.RegistrationServiceSenderExceptionMapper;
import org.whispersystems.textsecuregcm.push.PushNotificationManager;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.redis.RedisClusterExtension;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceClient;
import org.whispersystems.textsecuregcm.registration.VerificationSession;
import org.whispersystems.textsecuregcm.registration.risk.RegistrationRiskAssessor;
import org.whispersystems.textsecuregcm.registration.risk.RiskSignals;
import org.whispersystems.textsecuregcm.registration.risk.SourceNetworkClassifier;
import org.whispersystems.textsecuregcm.registration.risk.TestRiskConfig;
import org.whispersystems.textsecuregcm.spam.RegistrationFraudChecker;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.storage.PhoneNumberIdentifiers;
import org.whispersystems.textsecuregcm.storage.PhoneNumberRecoveryPasswordsManager;
import org.whispersystems.textsecuregcm.storage.VerificationSessionManager;
import org.whispersystems.textsecuregcm.telephony.CarrierDataProvider;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestClock;
import org.whispersystems.textsecuregcm.util.TestRemoteAddressFilterProvider;

/// ADR-0070 §十 P2 判据：**建会话接入判断，但只记录不放行；用户可见行为与今天逐字节一致；指标里能看到「本来会放行」的数量。**
///
/// - 逐字节一致：同一串请求分别打给「没有评估器」和「有评估器」的 `VerificationController`（评估器接真 Redis、接坏掉的 Redis、
///   接卡死的 Redis 三种），响应的状态、头、正文和其余依赖收到的调用全部相同
/// - 红控制：每个接入点（建会话 / 发码前 / 发码后 / 验码后）都被调用，且带着正确的信号；从 controller 里去掉任何一处，对应的用例必须变红
/// - 端到端：经由 controller 走一遍，指标里出现「本来会放行」
class VerificationControllerRiskRecordingTest {

  @RegisterExtension
  static final RedisClusterExtension REDIS_CLUSTER_EXTENSION = RedisClusterExtension.builder().build();

  private static final byte[] SESSION_ID = "session".getBytes(StandardCharsets.UTF_8);
  private static final String ENCODED_SESSION_ID = Base64.getUrlEncoder().encodeToString(SESSION_ID);
  private static final String NUMBER = "+8613800138000";
  private static final String CLIENT_IP = "203.0.113.9";
  private static final String USER_AGENT = "Signal-Android/0.1.2 Android/34 Build/175101";
  private static final long SESSION_EXPIRATION_SECONDS = Duration.ofMinutes(10).toSeconds();
  private static final UUID PNI = UUID.randomUUID();

  private final Clock clock = TestClock.pinned(Instant.ofEpochSecond(490_000L * 3600 + 1800));

  /// 一个完整的 controller + 它的全部依赖（mock）+ 一个 Jersey 测试服务器
  private final class Harness implements AutoCloseable {

    final RegistrationServiceClient registrationServiceClient = mock(RegistrationServiceClient.class);
    final VerificationSessionManager verificationSessionManager = mock(VerificationSessionManager.class);
    final PushNotificationManager pushNotificationManager = mock(PushNotificationManager.class);
    final RegistrationCaptchaManager registrationCaptchaManager = mock(RegistrationCaptchaManager.class);
    final PhoneNumberRecoveryPasswordsManager phoneNumberRecoveryPasswordsManager =
        mock(PhoneNumberRecoveryPasswordsManager.class);
    final PhoneNumberIdentifiers phoneNumberIdentifiers = mock(PhoneNumberIdentifiers.class);
    final RateLimiters rateLimiters = mock(RateLimiters.class);
    final AccountsManager accountsManager = mock(AccountsManager.class);
    final CarrierDataProvider carrierDataProvider = mock(CarrierDataProvider.class);
    @SuppressWarnings("unchecked")
    final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager =
        mock(DynamicConfigurationManager.class);
    final DynamicConfiguration dynamicConfiguration = mock(DynamicConfiguration.class);
    final ResourceExtension resources;

    Harness(final RegistrationRiskAssessor assessor) throws Throwable {
      when(rateLimiters.getVerificationCaptchaLimiter()).thenReturn(mock(RateLimiter.class));
      when(rateLimiters.getVerificationPushChallengeLimiter()).thenReturn(mock(RateLimiter.class));
      when(accountsManager.getByE164(any())).thenReturn(Optional.empty());
      when(dynamicConfiguration.getRegistrationConfiguration()).thenReturn(new DynamicRegistrationConfiguration(false));
      when(dynamicConfiguration.getCarrierDataLookupConfiguration()).thenReturn(new DynamicCarrierDataLookupConfiguration());
      when(dynamicConfigurationManager.getConfiguration()).thenReturn(dynamicConfiguration);
      when(phoneNumberIdentifiers.getPhoneNumberIdentifier(NUMBER))
          .thenReturn(CompletableFuture.completedFuture(PNI));

      resources = ResourceExtension.builder()
          .addProperty(ServerProperties.UNWRAP_COMPLETION_STAGE_IN_WRITER_ENABLE, Boolean.TRUE)
          .addProvider(new RateLimitExceededExceptionMapper())
          .addProvider(new ImpossiblePhoneNumberExceptionMapper())
          .addProvider(new NonNormalizedPhoneNumberExceptionMapper())
          .addProvider(new ObsoletePhoneNumberFormatExceptionMapper())
          .addProvider(new RegistrationServiceSenderExceptionMapper())
          .addProvider(new TestRemoteAddressFilterProvider(CLIENT_IP))
          .setMapper(SystemMapper.jsonMapper())
          .setTestContainerFactory(new GrizzlyWebTestContainerFactory())
          .addResource(new VerificationController(registrationServiceClient, verificationSessionManager,
              pushNotificationManager, registrationCaptchaManager, phoneNumberRecoveryPasswordsManager,
              phoneNumberIdentifiers, rateLimiters, accountsManager, carrierDataProvider,
              RegistrationFraudChecker.noop(), dynamicConfigurationManager, clock, assessor))
          .build();
      resources.before();
    }

    @Override
    public void close() throws Exception {
      try {
        resources.after();
      } catch (final Exception e) {
        throw e;
      } catch (final Throwable t) {
        throw new RuntimeException(t);
      }
    }

    Invocation.Builder request(final String path) {
      return resources.getJerseyTest().target(path).request().header(HttpHeaders.USER_AGENT, USER_AGENT);
    }

    RegistrationServiceSession session(final boolean verified) {
      return new RegistrationServiceSession(SESSION_ID, NUMBER, verified, null, null, 0L, SESSION_EXPIRATION_SECONDS);
    }

    VerificationSession storedSession(final boolean allowedToRequestCode) {
      return new VerificationSession(ENCODED_SESSION_ID, null, null,
          allowedToRequestCode ? Collections.emptyList() : List.of(VerificationSession.Information.CAPTCHA),
          Collections.emptyList(), null, null, allowedToRequestCode, clock.millis(), clock.millis(),
          SESSION_EXPIRATION_SECONDS);
    }

    /// 走一遍所有接了评估器的接口，返回每一步的响应
    List<Recorded> runScript() throws Exception {
      final List<Recorded> recorded = new ArrayList<>();

      // 建会话：没带推送 token
      when(registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any(), any(), any()))
          .thenReturn(session(false));
      recorded.add(Recorded.of(request("/v1/verification/session").post(Entity.json("{\"number\":\"" + NUMBER + "\"}"))));

      // 建会话：号码不合法（校验没过，评估器不会被调用）
      recorded.add(Recorded.of(request("/v1/verification/session").post(Entity.json("{\"number\":\"+1800\"}"))));

      // 发码：允许
      when(registrationServiceClient.getSession(any(), any())).thenReturn(Optional.of(session(false)));
      when(verificationSessionManager.findForId(any())).thenReturn(Optional.of(storedSession(true)));
      when(registrationServiceClient.sendVerificationCode(any(), any(), any(), any(), any(), any()))
          .thenReturn(session(false));
      recorded.add(Recorded.of(request("/v1/verification/session/" + ENCODED_SESSION_ID + "/code")
          .post(Entity.json("{\"transport\":\"sms\",\"client\":\"android\"}"))));

      // 发码：还没验证完（409）
      when(verificationSessionManager.findForId(any())).thenReturn(Optional.of(storedSession(false)));
      recorded.add(Recorded.of(request("/v1/verification/session/" + ENCODED_SESSION_ID + "/code")
          .post(Entity.json("{\"transport\":\"sms\",\"client\":\"android\"}"))));

      // 验码：验错
      when(registrationServiceClient.checkVerificationCode(any(), any(), any())).thenReturn(session(false));
      recorded.add(Recorded.of(request("/v1/verification/session/" + ENCODED_SESSION_ID + "/code")
          .put(Entity.json("{\"code\":\"000000\"}"))));

      // 验码：验对
      when(registrationServiceClient.checkVerificationCode(any(), any(), any())).thenReturn(session(true));
      recorded.add(Recorded.of(request("/v1/verification/session/" + ENCODED_SESSION_ID + "/code")
          .put(Entity.json("{\"code\":\"123456\"}"))));

      return recorded;
    }

    /// 所有依赖收到的调用（方法名 + 参数），用来证明评估器没有让 controller 多调或少调任何东西
    Map<String, List<String>> interactions() {
      final Map<String, List<String>> interactions = new TreeMap<>();
      for (final Object mock : List.of(registrationServiceClient, verificationSessionManager, pushNotificationManager,
          registrationCaptchaManager, phoneNumberRecoveryPasswordsManager, phoneNumberIdentifiers, accountsManager,
          carrierDataProvider)) {
        interactions.put(Mockito.mockingDetails(mock).getMockCreationSettings().getTypeToMock().getSimpleName(),
            Mockito.mockingDetails(mock).getInvocations().stream()
                .map(invocation -> invocation.getMethod().getName() + Arrays.deepToString(invocation.getArguments()))
                .toList());
      }
      return interactions;
    }
  }

  /// 一个响应里用户看得到的全部：状态、头（去掉每次都不同的 Date）、正文的原始字节
  private record Recorded(int status, Map<String, List<String>> headers, String body) {

    static Recorded of(final Response response) {
      try (response) {
        final Map<String, List<String>> headers = new TreeMap<>();
        response.getStringHeaders().forEach((name, values) -> {
          if (!name.equalsIgnoreCase("Date")) {
            headers.put(name.toLowerCase(), List.copyOf(values));
          }
        });
        return new Recorded(response.getStatus(), headers,
            new String(response.readEntity(byte[].class), StandardCharsets.UTF_8));
      }
    }
  }

  private RegistrationRiskAssessor enabledAssessor(final FaultTolerantRedisClusterClient cluster,
      final SimpleMeterRegistry meterRegistry) {

    return RegistrationRiskAssessor.create(TestRiskConfig.defaults(), cluster, clock, Runnable::run,
        meterRegistry, SourceNetworkClassifier.fromCidrBlocks(List.of()));
  }

  // 逐字节一致

  @Test
  void responsesAndCollaboratorCallsAreIdenticalWithAndWithoutTheAssessor() throws Throwable {
    final List<Recorded> baseline;
    final Map<String, List<String>> baselineInteractions;
    try (final Harness harness = new Harness(RegistrationRiskAssessor.disabled())) {
      baseline = harness.runScript();
      baselineInteractions = harness.interactions();
    }

    // 脚本本身要有意义：不是全 404，而且覆盖了 200 / 409 / 422
    assertThat(baseline).extracting(Recorded::status).containsExactly(200, 422, 200, 409, 200, 200);
    assertThat(baseline.get(5).body()).contains("\"verified\":true");

    final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    try (final Harness harness = new Harness(enabledAssessor(REDIS_CLUSTER_EXTENSION.getRedisCluster(), meterRegistry))) {
      assertThat(harness.runScript()).as("assessor on a working Redis").isEqualTo(baseline);
      assertThat(harness.interactions()).isEqualTo(baselineInteractions);
    }
    // ……并且它确实在工作（不是因为根本没跑才一致）
    assertThat(meterRegistry.find("chat.RegistrationRiskAssessor.assessment").counters()).isNotEmpty();
  }

  @Test
  void aBrokenRedisChangesNothingTheCallerCanSee() throws Throwable {
    final List<Recorded> baseline;
    final Map<String, List<String>> baselineInteractions;
    try (final Harness harness = new Harness(RegistrationRiskAssessor.disabled())) {
      baseline = harness.runScript();
      baselineInteractions = harness.interactions();
    }

    final FaultTolerantRedisClusterClient brokenCluster = mock(FaultTolerantRedisClusterClient.class);
    when(brokenCluster.withCluster(any())).thenThrow(new RuntimeException("connection refused"));
    final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

    try (final Harness harness = new Harness(enabledAssessor(brokenCluster, meterRegistry))) {
      assertThat(harness.runScript()).as("assessor on a Redis that always fails").isEqualTo(baseline);
      assertThat(harness.interactions()).isEqualTo(baselineInteractions);
    }

    // 失败只留在指标里：建会话 / 发码前 / 发码后 / 验码后各一步（脚本里发码成功 1 次、验码 2 次、建会话 1 次）
    assertThat(errors(meterRegistry, "session")).isEqualTo(1);
    assertThat(errors(meterRegistry, "preSend")).isEqualTo(1);
    assertThat(errors(meterRegistry, "codeSent")).isEqualTo(1);
    assertThat(errors(meterRegistry, "codeChecked")).isEqualTo(2);
  }

  private static double errors(final SimpleMeterRegistry meterRegistry, final String stage) {
    return meterRegistry.find("chat.RegistrationRiskAssessor.error").tags("stage", stage, "kind", "unavailable")
        .counters().stream().mapToDouble(Counter::count).sum();
  }

  @Test
  @Timeout(value = 120, unit = TimeUnit.SECONDS)
  void aStuckRedisDoesNotSlowDownTheRequestsAndTheResponsesStayIdentical() throws Throwable {
    final List<Recorded> baseline;
    try (final Harness harness = new Harness(RegistrationRiskAssessor.disabled())) {
      baseline = harness.runScript();
    }

    final CountDownLatch redisIsStuck = new CountDownLatch(1);
    final FaultTolerantRedisClusterClient stuckCluster = mock(FaultTolerantRedisClusterClient.class);
    when(stuckCluster.withCluster(any())).thenAnswer(invocation -> {
      redisIsStuck.await();
      throw new RuntimeException("timed out");
    });

    // 和线上一样：少量线程 + 有界队列。1 个线程被卡死的 Redis 占住，队列 2，其余的记录被丢弃
    final ThreadPoolExecutor executor = new ThreadPoolExecutor(1, 1, 0, TimeUnit.SECONDS, new ArrayBlockingQueue<>(2));
    final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    final RegistrationRiskAssessor assessor = RegistrationRiskAssessor.create(
        TestRiskConfig.defaults(), stuckCluster, clock, executor, meterRegistry,
        SourceNetworkClassifier.fromCidrBlocks(List.of()));

    try (final Harness harness = new Harness(assessor)) {
      final long start = System.nanoTime();
      final List<Recorded> recorded = harness.runScript();
      final Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

      assertThat(recorded).isEqualTo(baseline);
      // 整串请求（含 Jersey 启动后的第一次调用）不到几秒；如果评估在请求线程上等 Redis，这里会一直等到测试超时
      assertThat(elapsed).isLessThan(Duration.ofSeconds(10));
    } finally {
      redisIsStuck.countDown();
      executor.shutdown();
      assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
    }

    // 6 个请求里 5 步触发记录（建会话 1、发码前 1、发码后 1、验码后 2）：1 个在跑、2 个排队、2 个被丢弃
    assertThat(meterRegistry.find("chat.RegistrationRiskAssessor.error").tags("kind", "dropped").counters().stream()
        .mapToDouble(Counter::count).sum()).isEqualTo(2);
  }

  // 红控制：每个接入点都被调用，带着正确的信号。从 controller 里去掉任何一处，对应的断言必须变红

  @Test
  void everyStepFeedsTheAssessorWithTheRightSignals() throws Throwable {
    final RegistrationRiskAssessor assessor = mock(RegistrationRiskAssessor.class);

    try (final Harness harness = new Harness(assessor)) {
      harness.runScript();
    }

    // 建会话：来源地址是 RemoteAddressFilter 给的那个，User-Agent 原样，会话号 = 注册服务返回的
    verify(assessor, times(1)).sessionCreated(
        new RiskSignals(CLIENT_IP, NUMBER, USER_AGENT, ENCODED_SESSION_ID, false));

    // 发码前：只在真的要发码时调用一次（409 那次在这之前就返回了）
    verify(assessor, times(1)).codeRequested(
        new RiskSignals(CLIENT_IP, NUMBER, USER_AGENT, ENCODED_SESSION_ID, false));

    // 发码后：只在发码成功时
    verify(assessor, times(1)).codeSent(RiskSignals.forSession(NUMBER, ENCODED_SESSION_ID));

    // 验码后：验错一次、验对一次
    verify(assessor, times(1)).codeChecked(RiskSignals.forSession(NUMBER, ENCODED_SESSION_ID), false);
    verify(assessor, times(1)).codeChecked(RiskSignals.forSession(NUMBER, ENCODED_SESSION_ID), true);

    Mockito.verifyNoMoreInteractions(assessor);
  }

  @Test
  void aSessionCreatedWithAPushTokenIsMarkedAsSuch() throws Throwable {
    final RegistrationRiskAssessor assessor = mock(RegistrationRiskAssessor.class);

    try (final Harness harness = new Harness(assessor)) {
      when(harness.registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any(), any(), any()))
          .thenReturn(harness.session(false));

      try (final Response response = harness.request("/v1/verification/session")
          .post(Entity.json("{\"number\":\"" + NUMBER + "\",\"pushToken\":\"token\",\"pushTokenType\":\"fcm\"}"))) {
        assertThat(response.getStatus()).isEqualTo(200);
      }
    }

    verify(assessor).sessionCreated(new RiskSignals(CLIENT_IP, NUMBER, USER_AGENT, ENCODED_SESSION_ID, true));
  }

  @Test
  void requestsThatFailBeforeTheirStepNeverReachTheAssessor() throws Throwable {
    final RegistrationRiskAssessor assessor = mock(RegistrationRiskAssessor.class);

    try (final Harness harness = new Harness(assessor)) {
      // 注册服务建会话失败 → 没有会话，没有记录
      when(harness.registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any(), any(), any()))
          .thenThrow(new RuntimeException("expected service error"));
      try (final Response response = harness.request("/v1/verification/session")
          .post(Entity.json("{\"number\":\"" + NUMBER + "\"}"))) {
        assertThat(response.getStatus()).isEqualTo(500);
      }

      // 会话已经验证过 → 发码 409、验码 409：都没有记录
      when(harness.registrationServiceClient.getSession(any(), any())).thenReturn(Optional.of(harness.session(true)));
      when(harness.verificationSessionManager.findForId(any())).thenReturn(Optional.of(harness.storedSession(true)));
      try (final Response response = harness.request("/v1/verification/session/" + ENCODED_SESSION_ID + "/code")
          .post(Entity.json("{\"transport\":\"sms\",\"client\":\"android\"}"))) {
        assertThat(response.getStatus()).isEqualTo(409);
      }
      try (final Response response = harness.request("/v1/verification/session/" + ENCODED_SESSION_ID + "/code")
          .put(Entity.json("{\"code\":\"123456\"}"))) {
        assertThat(response.getStatus()).isEqualTo(409);
      }
    }

    Mockito.verifyNoInteractions(assessor);
  }

  // 端到端：真评估器 + 真 Redis，经由 controller 走一遍，指标里出现「本来会放行」

  @Test
  void aFreshRegistrationIsRecordedAsWouldHaveBeenAllowedButStillGetsACaptchaRequest() throws Throwable {
    final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

    try (final Harness harness = new Harness(enabledAssessor(REDIS_CLUSTER_EXTENSION.getRedisCluster(), meterRegistry))) {
      when(harness.registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any(), any(), any()))
          .thenReturn(harness.session(false));

      try (final Response response = harness.request("/v1/verification/session")
          .post(Entity.json("{\"number\":\"" + NUMBER + "\"}"))) {
        assertThat(response.getStatus()).isEqualTo(200);
        // 用户可见的部分和今天一样：仍然无条件要验证码，不放行
        assertThat(response.readEntity(String.class))
            .contains("\"allowedToRequestCode\":false")
            .contains("\"requestedInformation\":[\"captcha\"]");
      }

      final ArgumentCaptor<VerificationSession> stored = ArgumentCaptor.forClass(VerificationSession.class);
      verify(harness.verificationSessionManager).insert(stored.capture());
      assertThat(stored.getValue().requestedInformation()).containsExactly(VerificationSession.Information.CAPTCHA);
      assertThat(stored.getValue().allowedToRequestCode()).isFalse();
      verify(harness.verificationSessionManager, never()).update(any());
    }

    // ……而评估器记下了：这次本来会放行
    assertThat(meterRegistry.find("chat.RegistrationRiskAssessor.assessment")
        .tags("stage", "session", "outcome", "wouldAllow", "failed", "none", "platform", "android", "push", "false")
        .counters().stream().mapToDouble(Counter::count).sum()).isEqualTo(1);
  }

  @Test
  void theSameNumberAskingAgainAfterACodeWentOutIsRecordedAsWouldNotHaveBeenAllowed() throws Throwable {
    final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();

    try (final Harness harness = new Harness(enabledAssessor(REDIS_CLUSTER_EXTENSION.getRedisCluster(), meterRegistry))) {
      when(harness.registrationServiceClient.createRegistrationSession(any(), anyString(), anyBoolean(), any(), any(), any()))
          .thenReturn(harness.session(false));
      when(harness.registrationServiceClient.getSession(any(), any())).thenReturn(Optional.of(harness.session(false)));
      when(harness.verificationSessionManager.findForId(any())).thenReturn(Optional.of(harness.storedSession(true)));
      when(harness.registrationServiceClient.sendVerificationCode(any(), any(), any(), any(), any(), any()))
          .thenReturn(harness.session(false));

      final String body = "{\"number\":\"" + NUMBER + "\"}";
      harness.request("/v1/verification/session").post(Entity.json(body)).close();
      harness.request("/v1/verification/session/" + ENCODED_SESSION_ID + "/code")
          .post(Entity.json("{\"transport\":\"sms\",\"client\":\"android\"}")).close();
      harness.request("/v1/verification/session").post(Entity.json(body)).close();
    }

    final double wouldAllow = meterRegistry.find("chat.RegistrationRiskAssessor.assessment")
        .tags("stage", "session", "outcome", "wouldAllow").counters().stream().mapToDouble(Counter::count).sum();
    final double condition1 = meterRegistry.find("chat.RegistrationRiskAssessor.conditionFailed")
        .tags("stage", "session", "condition", "first-code", "reason", "code-already-sent")
        .counters().stream().mapToDouble(Counter::count).sum();

    assertThat(wouldAllow).isEqualTo(1);
    assertThat(condition1).isEqualTo(1);
  }
}
