/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.captcha;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.altcha.altcha.v2.Altcha;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.configuration.AltchaCaptchaConfiguration;
import org.whispersystems.textsecuregcm.configuration.AltchaCaptchaConfiguration.Tier;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicCaptchaConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import org.whispersystems.textsecuregcm.redis.RedisClusterExtension;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.TestClock;

/// ADR-0070 §10 判据 ④⑤⑥：重放 / 过期 / action 不符各自被拒；同一网段逐档升难度但始终签发、始终能完成，别的网段仍是最低档。
/// Redis 用真的（testcontainers 集群），一次性检查走的就是线上那条 SET NX EX。
class AltchaCaptchaClientTest {

  @RegisterExtension
  static final RedisClusterExtension REDIS_CLUSTER_EXTENSION = RedisClusterExtension.builder().build();

  // 测试用小难度（线上是 1,000–5,000 次迭代 × 5,000–30,000 计数），每档都在毫秒级解完；形状和线上一样：三档、两个阈值
  private static final List<Tier> TEST_TIERS = List.of(new Tier(1, 5, 10), new Tier(2, 20, 30), new Tier(3, 40, 50));
  private static final List<Integer> TEST_THRESHOLDS = List.of(3, 6);

  private TestClock clock;
  private AltchaCaptchaClient client;

  @BeforeEach
  void setUp() {
    // 官方库按系统时钟判过期，所以把测试时钟钉在「现在」附近
    clock = TestClock.pinned(Instant.now());
    client = client("k1", "secret-one", null, null, 1_000);
  }

  private AltchaCaptchaClient client(final String keyId, final String secret, final String previousKeyId,
      final String previousSecret, final int globalBudget) {

    return new AltchaCaptchaClient(new AltchaCaptchaConfiguration(keyId, new SecretString(secret), previousKeyId,
        previousSecret == null ? null : new SecretString(previousSecret), Duration.ofMinutes(10), TEST_TIERS,
        TEST_THRESHOLDS, globalBudget), REDIS_CLUSTER_EXTENSION.getRedisCluster(), clock);
  }

  /// 像控件那样解题并组出令牌：`altcha.<kid>.<action>.<base64url(JSON.stringify({challenge, solution}))>`
  static String solveToToken(final String challengeJson, final String action) throws Exception {
    final Altcha.Challenge challenge = parseChallenge(challengeJson);
    final Altcha.Solution solution = Altcha.solveChallenge(challenge, Altcha.pbkdf2());
    // 控件的 time 是带一位小数的毫秒（worker 里 Math.floor(x * 10) / 10）
    final String payload = "{\"challenge\":" + challengeJson + ",\"solution\":{\"counter\":" + solution.counter()
        + ",\"derivedKey\":\"" + solution.derivedKey() + "\",\"time\":" + solution.time() + ".5}}";
    return "altcha." + challenge.parameters().data().get("kid") + "." + action + "."
        + Base64.getUrlEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8));
  }

  static Altcha.Challenge parseChallenge(final String challengeJson) throws Exception {
    final String wrapper = "{\"challenge\":" + challengeJson + ",\"solution\":{\"counter\":0,\"derivedKey\":\"00\"}}";
    return Altcha.parsePayload(Base64.getEncoder().encodeToString(wrapper.getBytes(StandardCharsets.UTF_8))).challenge();
  }

  private static String payloadPart(final String token) {
    return token.split("\\.", 4)[3];
  }

  private AssessmentResult verify(final String token, final Action action) {
    final String[] parts = token.split("\\.", 4);
    return client.verify(Optional.empty(), parts[1], action, parts[3], "10.0.0.1", "ua");
  }

  private static int tierOf(final AltchaCaptchaClient.IssuedChallenge issued) throws Exception {
    return Integer.parseInt((String) parseChallenge(issued.json()).parameters().data().get("tier"));
  }

  @Test
  void acceptsSolvedChallenge() throws Exception {
    final AltchaCaptchaClient.IssuedChallenge issued = client.issueChallenge(Action.REGISTRATION, "10.0.0.1", "primary");
    final Altcha.ChallengeParameters parameters = parseChallenge(issued.json()).parameters();

    assertThat(parameters.algorithm()).isEqualTo("PBKDF2/SHA-256");
    assertThat(parameters.data()).containsEntry("action", "registration").containsEntry("kid", "k1").containsEntry("tier", "0");
    assertThat(parameters.expiresAt()).isEqualTo(clock.instant().plus(Duration.ofMinutes(10)).getEpochSecond());
    assertThat(parameters.keySignature()).isNotNull();

    final String token = solveToToken(issued.json(), "registration");
    assertThat(token).matches("altcha\\.k1\\.registration\\.[A-Za-z0-9_-]+");
    assertThat(verify(token, Action.REGISTRATION).isValid()).isTrue();
  }

  @Test
  void replayRejected() throws Exception {
    final String token = solveToToken(client.issueChallenge(Action.REGISTRATION, "10.0.0.1", "primary").json(), "registration");

    assertThat(verify(token, Action.REGISTRATION).isValid()).as("first use").isTrue();
    assertThat(verify(token, Action.REGISTRATION).isValid()).as("replayed token must be rejected").isFalse();
  }

  @Test
  void replayRejectedAcrossInstances() throws Exception {
    // 香港只有一台，但一次性记录在 Redis 里，不在进程内：另一个实例（或重启之后）照样认得出重放
    final String token = solveToToken(client.issueChallenge(Action.REGISTRATION, "10.0.0.1", "primary").json(), "registration");
    final AltchaCaptchaClient other = client("k1", "secret-one", null, null, 1_000);

    assertThat(verify(token, Action.REGISTRATION).isValid()).isTrue();
    assertThat(other.verify(Optional.empty(), "k1", Action.REGISTRATION, payloadPart(token), "10.0.0.2", null).isValid())
        .as("replayed token must be rejected by another instance").isFalse();
  }

  @Test
  void expiredRejectedBySignedExpiry() throws Exception {
    // 挑战签发于 20 分钟前（有效期 10 分钟）：官方库按签名里的 expiresAt 判过期
    clock.pin(Instant.now().minus(Duration.ofMinutes(20)));
    final String token = solveToToken(client.issueChallenge(Action.REGISTRATION, "10.0.0.1", "primary").json(), "registration");
    clock.pin(Instant.now());

    assertThat(verify(token, Action.REGISTRATION).isValid()).as("expired token must be rejected").isFalse();
  }

  @Test
  void expiredRejectedByServerClock() throws Exception {
    // 系统时钟还在有效期里，服务端时钟（注入的）已经过了：也要拒
    final String token = solveToToken(client.issueChallenge(Action.REGISTRATION, "10.0.0.1", "primary").json(), "registration");
    clock.pin(clock.instant().plus(Duration.ofMinutes(11)));

    assertThat(verify(token, Action.REGISTRATION).isValid()).as("token past expiresAt on the server clock must be rejected")
        .isFalse();
  }

  @Test
  void actionMismatchRejected() throws Exception {
    // 挑战是给「限流挑战」签发的，拿去注册：令牌前缀照着注册写，但签过名的 data.action 对不上
    final String token = solveToToken(client.issueChallenge(Action.CHALLENGE, "10.0.0.1", "primary").json(), "registration");

    assertThat(verify(token, Action.REGISTRATION).isValid()).as("token issued for another action must be rejected").isFalse();
    // 不因为被拒而「用掉」：拿回它本来的 action 还能用一次
    assertThat(verify(token, Action.CHALLENGE).isValid()).isTrue();
  }

  @Test
  void actionMismatchRejectedByCaptchaChecker() throws Exception {
    // 令牌前缀里的 action 和这次要的不一样：CaptchaChecker 直接当参数错误（400），走不到 ALTCHA 校验
    final String token = solveToToken(client.issueChallenge(Action.CHALLENGE, "10.0.0.1", "primary").json(), "challenge");
    final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager = mock(DynamicConfigurationManager.class);
    final DynamicConfiguration dynamicConfiguration = mock(DynamicConfiguration.class);
    when(dynamicConfigurationManager.getConfiguration()).thenReturn(dynamicConfiguration);
    when(dynamicConfiguration.getCaptchaConfiguration()).thenReturn(new DynamicCaptchaConfiguration());
    final CaptchaChecker checker = new CaptchaChecker(null, scheme -> "altcha".equals(scheme) ? client : null,
        dynamicConfigurationManager);

    assertThrows(InvalidCaptchaArgumentException.class,
        () -> checker.verify(Optional.empty(), Action.REGISTRATION, token, "10.0.0.1", null));
    assertThat(checker.verify(Optional.empty(), Action.CHALLENGE, token, "10.0.0.1", null).isValid()).isTrue();
  }

  @Test
  void tamperedChallengeRejected() throws Exception {
    // 把挑战里的 action 从 challenge 改成 registration 再解：签名对不上
    final String issuedJson = client.issueChallenge(Action.CHALLENGE, "10.0.0.1", "primary").json();
    final ObjectNode tree = (ObjectNode) SystemMapper.jsonMapper().readTree(issuedJson);
    ((ObjectNode) tree.get("parameters").get("data")).put("action", "registration");
    final String token = solveToToken(SystemMapper.jsonMapper().writeValueAsString(tree), "registration");

    assertThat(verify(token, Action.REGISTRATION).isValid()).isFalse();
  }

  @Test
  void otherKeyRejected() throws Exception {
    final AltchaCaptchaClient other = client("k1", "some-other-secret", null, null, 1_000);
    final String token = solveToToken(other.issueChallenge(Action.REGISTRATION, "10.0.0.1", "primary").json(), "registration");

    assertThat(verify(token, Action.REGISTRATION).isValid()).isFalse();
    assertThat(client.validSiteKeys(Action.REGISTRATION)).containsExactly("k1");
  }

  @Test
  void previousKeyAcceptedDuringRotation() throws Exception {
    // 轮换：k1 → k2。换钥匙前签发的 k1 挑战在有效期内仍然认；新挑战用 k2 签
    final String oldToken = solveToToken(client.issueChallenge(Action.REGISTRATION, "10.0.0.1", "primary").json(), "registration");
    final AltchaCaptchaClient rotated = client("k2", "secret-two", "k1", "secret-one", 1_000);

    assertThat(rotated.validSiteKeys(Action.REGISTRATION)).containsExactlyInAnyOrder("k1", "k2");
    assertThat(rotated.verify(Optional.empty(), "k1", Action.REGISTRATION, payloadPart(oldToken), "10.0.0.1", null).isValid())
        .isTrue();

    final String newToken = solveToToken(rotated.issueChallenge(Action.REGISTRATION, "10.0.0.1", "primary").json(), "registration");
    assertThat(newToken).startsWith("altcha.k2.registration.");
    assertThat(rotated.verify(Optional.empty(), "k2", Action.REGISTRATION, payloadPart(newToken), "10.0.0.1", null).isValid())
        .isTrue();
  }

  @ParameterizedTest
  @ValueSource(strings = {
      "",
      "not base64!",
      "eyJ0ZXN0Ijp0cnVlfQ",   // {"test":true}
      "eyJjaGFsbGVuZ2UiOm51bGwsInNvbHV0aW9uIjpudWxsLCJ0ZXN0Ijp0cnVlfQ",   // 控件 test 模式：{"challenge":null,"solution":null,"test":true}
      "a+b/c==",   // 标准 base64 的字符不收（回跳地址只认 [A-Za-z0-9._-]）
  })
  void malformedRejected(final String payload) {
    assertThat(client.verify(Optional.empty(), "k1", Action.REGISTRATION, payload, "10.0.0.1", null).isValid()).isFalse();
  }

  @Test
  void overlongTokenRejected() {
    assertThat(client.verify(Optional.empty(), "k1", Action.REGISTRATION, "A".repeat(AltchaCaptchaClient.MAX_TOKEN_LENGTH + 1),
        "10.0.0.1", null).isValid()).isFalse();
  }

  @Test
  void difficultyStepsUpPerSegmentWithoutRefusal() throws Exception {
    // 同一个 /24 里不同的地址算同一个来源：阈值 3 / 6 → 第 1–3 个 T0、4–6 个 T1、之后一直 T2；从不拒绝
    final List<Integer> tiers = new ArrayList<>();
    AltchaCaptchaClient.IssuedChallenge last = null;
    for (int i = 1; i <= 12; i++) {
      last = client.issueChallenge(Action.REGISTRATION, "203.0.113." + i, "primary");
      tiers.add(tierOf(last));
    }
    assertThat(tiers).containsExactly(0, 0, 0, 1, 1, 1, 2, 2, 2, 2, 2, 2);

    // 每档的参数照配置：最高档的 cost 和计数范围
    final Altcha.ChallengeParameters hardest = parseChallenge(last.json()).parameters();
    assertThat(hardest.cost()).isEqualTo(3);

    // 最高档照样能解、能通过
    final String token = solveToToken(last.json(), "registration");
    assertThat(verify(token, Action.REGISTRATION).isValid()).as("the hardest tier must still be solvable").isTrue();

    // 别的网段不受影响
    assertThat(tierOf(client.issueChallenge(Action.REGISTRATION, "203.0.114.7", "primary"))).isZero();
    assertThat(tierOf(client.issueChallenge(Action.REGISTRATION, "2001:db8:1:2::1", "primary"))).isZero();
  }

  @Test
  void ipv6SegmentIsSlash56() throws Exception {
    // 2001:db8:1:200::/56 里的两个地址算同一个来源，2001:db8:1:300:: 是另一个
    for (int i = 0; i < 4; i++) {
      client.issueChallenge(Action.REGISTRATION, "2001:db8:1:2" + (i % 2 == 0 ? "00" : "ff") + "::" + (i + 1), "primary");
    }
    assertThat(tierOf(client.issueChallenge(Action.REGISTRATION, "2001:db8:1:2aa::9", "primary"))).isEqualTo(1);
    assertThat(tierOf(client.issueChallenge(Action.REGISTRATION, "2001:db8:1:300::9", "primary"))).isZero();
  }

  @Test
  void globalBudgetStepsEveryoneUpOneTierWithoutRefusal() throws Exception {
    // 全局预算 5：第 6 个起，哪怕来自从没见过的网段，也整体加一档（不拒）
    client = client("k1", "secret-one", null, null, 5);
    for (int i = 1; i <= 5; i++) {
      final AltchaCaptchaClient.IssuedChallenge issued = client.issueChallenge(Action.REGISTRATION, "198.51." + i + ".1", "primary");
      assertThat(tierOf(issued)).isZero();
      assertThat(issued.globalStepUp()).isFalse();
    }
    final AltchaCaptchaClient.IssuedChallenge sixth = client.issueChallenge(Action.REGISTRATION, "198.51.100.1", "primary");
    assertThat(tierOf(sixth)).isEqualTo(1);
    assertThat(sixth.globalStepUp()).isTrue();
    assertThat(verify(solveToToken(sixth.json(), "registration"), Action.REGISTRATION).isValid()).isTrue();
  }

  @Test
  void countsSlideAcrossTheHour() throws Exception {
    // 上一个整点桶按剩余比例计入：59 分时签了 4 个（T1 起点），过了整点 1 分钟仍约等于 4 个 → 还是 T1，不会整点清零
    clock.pin(Instant.ofEpochSecond((Instant.now().getEpochSecond() / 3600) * 3600 - 60));
    for (int i = 0; i < 4; i++) {
      client.issueChallenge(Action.REGISTRATION, "192.0.2.1", "primary");
    }
    clock.pin(clock.instant().plus(Duration.ofMinutes(2)));
    assertThat(tierOf(client.issueChallenge(Action.REGISTRATION, "192.0.2.1", "primary"))).isEqualTo(1);
  }

  @ParameterizedTest
  @CsvSource({
      "1, 1, 0", "3, 1, 0", "4, 1, 1", "6, 1, 1", "7, 1, 2", "1000000, 1, 2",
      "1, 11, 1", "4, 11, 2", "7, 11, 2",
  })
  void selectTier(final long segmentCount, final long globalCount, final int expectedTier) {
    assertThat(AltchaCaptchaClient.selectTier(segmentCount, globalCount, TEST_THRESHOLDS, 10)).isEqualTo(expectedTier);
  }

  @ParameterizedTest
  @CsvSource({
      "203.0.113.77, 203.0.113.0/24",
      "::ffff:203.0.113.77, 203.0.113.0/24",
      "2001:db8:1234:56ff:1:2:3:4, 2001:db8:1234:5600::/56",
      "not-an-ip, unknown",
      "'', unknown",
  })
  void segmentOf(final String ip, final String segment) {
    assertThat(AltchaCaptchaClient.segmentOf(ip)).isEqualTo(segment);
  }

  @Test
  void challengeJsonIsWhatTheWidgetExpects() throws Exception {
    // 控件 3.x（isChallengeValid）要 parameters.{algorithm, nonce, salt, keyPrefix}；页面从 data.kid / data.tier 拼令牌、定换路时限
    final JsonNode json = SystemMapper.jsonMapper().readTree(client.issueChallenge(Action.CHALLENGE, null, null).json());
    assertThat(json.get("signature").asText()).matches("[0-9a-f]{64}");
    assertThat(json.get("parameters").get("keyPrefix").asText()).matches("[0-9a-f]{32}");
    assertThat(json.get("parameters").get("data").get("action").asText()).isEqualTo("challenge");
    assertThat(json.get("parameters").get("data").get("kid").asText()).isEqualTo("k1");
  }
}
