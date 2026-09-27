/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.captcha;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.InetAddresses;
import io.lettuce.core.SetArgs;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Metrics;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.altcha.altcha.v2.Altcha;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.AltchaCaptchaConfiguration;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;

/// Tellomi（ADR-0070 §5.2–5.4）：自托管工作量证明 ALTCHA。大陆访客的验证页（nginx 按网段分流）用它，海外仍是 Turnstile。
///
/// **签发**（{@link #issueChallenge}，验证页经 `GET /v1/tellomi/captcha/altcha/challenge` 调用）：官方库 v2 的确定模式——服务端
/// 在 [minCounter, maxCounter] 里随机定目标计数，派生一次、把派生结果的前 16 字节当前缀交给控件，控件从 0 数到那里。挑战里带
/// HMAC 保护的 `data`：`action`（registration / challenge）、`tier`（难度档）、`kid`（密钥编号）。难度按来源网段最近一小时的
/// 签发量逐档升高（IPv4 /24、IPv6 /56），全局超预算时整体加一档；**任何情况下都签发**，只让可疑来源多算几秒（§2.1、§5.4）。
///
/// **校验**（{@link #verify}，令牌 `altcha.<kid>.<action>.<base64url(控件提交内容)>`）按顺序：
/// 1. 官方库：有效期、挑战签名、派生结果签名（`Altcha.verifySolution`）；
/// 2. 自己再按注入的时钟核一次有效期（库只认系统时钟）；
/// 3. action：挑战里签过名的 `data.action` 必须等于这次要的 action（令牌前缀里的 action 由 `CaptchaChecker` 另核）；
/// 4. **一次性**：`SET altcha::used::<nonce> 1 NX EX <剩余秒数>`，已存在就拒（官方库不做防重放，§5.2）。
///
/// 计数的键用带密钥的哈希，不存 IP 原文；日志不写令牌和 IP。
public class AltchaCaptchaClient implements CaptchaClient {

  public static final String SCHEME = "altcha";

  static final String ALGORITHM = "PBKDF2/SHA-256";
  static final String DATA_ACTION = "action";
  static final String DATA_TIER = "tier";
  static final String DATA_KEY_ID = "kid";

  /// 控件提交内容约 450 字节 JSON（base64 后约 600 字符）；留足余量，但不给超长输入解码的机会
  static final int MAX_TOKEN_LENGTH = 4096;
  private static final Pattern BASE64URL = Pattern.compile("[A-Za-z0-9_-]+={0,2}");

  static final String USED_NONCE_KEY_PREFIX = "altcha::used::";
  private static final String COUNTER_KEY_PREFIX = "altcha::issued::";
  private static final String GLOBAL_COUNTER = "global";
  private static final long WINDOW_SECONDS = 3600;

  private static final Logger logger = LoggerFactory.getLogger(AltchaCaptchaClient.class);

  private static final String CHALLENGE_COUNTER_NAME = name(AltchaCaptchaClient.class, "challenge");
  private static final String VERIFY_COUNTER_NAME = name(AltchaCaptchaClient.class, "verify");
  private static final String SOLVE_MILLIS_NAME = name(AltchaCaptchaClient.class, "solveMillis");
  private static final String BUDGET_EXCEEDED_COUNTER_NAME = name(AltchaCaptchaClient.class, "globalBudgetExceeded");
  private static final String COUNTER_FAILURE_COUNTER_NAME = name(AltchaCaptchaClient.class, "counterFailure");

  /// 页面换路 / 重试的原因白名单（指标标签，基数有限）
  static final Set<String> VIA_VALUES = Set.of("primary", "fallback-load", "fallback-error", "fallback-timeout",
      "fallback-unsupported", "manual", "retry");

  private final AltchaCaptchaConfiguration configuration;
  private final FaultTolerantRedisClusterClient redisCluster;
  private final Clock clock;
  private final SecureRandom random = new SecureRandom();
  private final Map<String, DerivedSecrets> secretsByKeyId;
  private final DerivedSecrets current;
  private final Set<String> siteKeys;
  private final AtomicLong lastBudgetWarningWindow = new AtomicLong(-1);

  private record DerivedSecrets(String signatureSecret, String keySignatureSecret, byte[] counterKey) {

    static DerivedSecrets from(final String masterSecret) {
      return new DerivedSecrets(
          HexFormat.of().formatHex(hmac(masterSecret.getBytes(StandardCharsets.UTF_8), "tellomi-altcha/challenge-signature")),
          HexFormat.of().formatHex(hmac(masterSecret.getBytes(StandardCharsets.UTF_8), "tellomi-altcha/key-signature")),
          hmac(masterSecret.getBytes(StandardCharsets.UTF_8), "tellomi-altcha/issuance-counter"));
    }
  }

  /// 一次签发的结果：`json` 原样交给控件
  public record IssuedChallenge(String json, int tier, boolean globalStepUp) {
  }

  public AltchaCaptchaClient(final AltchaCaptchaConfiguration configuration,
      final FaultTolerantRedisClusterClient redisCluster,
      final Clock clock) {

    this.configuration = configuration;
    this.redisCluster = redisCluster;
    this.clock = clock;
    this.current = DerivedSecrets.from(configuration.secret().value());

    final Map<String, DerivedSecrets> byKeyId = new LinkedHashMap<>();
    byKeyId.put(configuration.keyId(), current);
    if (configuration.previousKeyId() != null && configuration.previousSecret() != null) {
      byKeyId.put(configuration.previousKeyId(), DerivedSecrets.from(configuration.previousSecret().value()));
    }
    this.secretsByKeyId = Map.copyOf(byKeyId);
    this.siteKeys = Set.copyOf(byKeyId.keySet());
  }

  @Override
  public String scheme() {
    return SCHEME;
  }

  @Override
  public Set<String> validSiteKeys(final Action action) {
    return siteKeys;
  }

  /// 签发一个挑战。**从不拒绝**：来源越热、难度越高（§5.4）。计数用的 Redis 出错时按最低档签发（难度只是减速带，不值得因此挡人）。
  ///
  /// @param action 挑战绑定的 action，签进 `data`，校验时必须一致
  /// @param ip     访问者地址（nginx 覆盖过的 X-Forwarded-For），只用来算网段
  /// @param via    页面为什么来要挑战（首选 / 从 Turnstile 换过来 / 重试）；不在白名单里记成 other
  public IssuedChallenge issueChallenge(final Action action, @Nullable final String ip, @Nullable final String via)
      throws Exception {

    final long segmentCount = countIssuance(segmentCounterName(ip));
    final long globalCount = countIssuance(GLOBAL_COUNTER);
    final boolean globalStepUp = globalCount > configuration.globalHourlyBudget();
    final int tier = selectTier(segmentCount, globalCount, configuration.segmentThresholds(),
        configuration.globalHourlyBudget());

    if (globalStepUp) {
      final long window = clock.instant().getEpochSecond() / WINDOW_SECONDS;
      if (lastBudgetWarningWindow.getAndSet(window) != window) {
        logger.warn("ALTCHA global hourly budget {} exceeded ({} issued in the last hour): every source is one tier harder",
            configuration.globalHourlyBudget(), globalCount);
      }
      Metrics.counter(BUDGET_EXCEEDED_COUNTER_NAME).increment();
    }

    final AltchaCaptchaConfiguration.Tier difficulty = configuration.tiers().get(tier);
    final Altcha.Challenge challenge = Altcha.createChallenge(new Altcha.CreateChallengeOptions()
        .algorithm(ALGORITHM)
        .cost(difficulty.cost())
        .counter(random.nextInt(difficulty.minCounter(), difficulty.maxCounter() + 1))
        .data(Map.of(
            DATA_ACTION, action.getActionName(),
            DATA_TIER, Integer.toString(tier),
            DATA_KEY_ID, configuration.keyId()))
        .expiresAt(clock.instant().plus(configuration.challengeTtl()).getEpochSecond())
        .hmacSignatureSecret(current.signatureSecret())
        .hmacKeySignatureSecret(current.keySignatureSecret()));

    Metrics.counter(CHALLENGE_COUNTER_NAME,
            "action", action.getActionName(),
            "tier", Integer.toString(tier),
            "via", via != null && VIA_VALUES.contains(via) ? via : "other",
            "globalStepUp", Boolean.toString(globalStepUp))
        .increment();

    return new IssuedChallenge(challenge.toJson(), tier, globalStepUp);
  }

  @Override
  public AssessmentResult verify(final Optional<UUID> maybeAci, final String siteKey, final Action action,
      final String token, final String ip, @Nullable final String userAgent) {

    final DerivedSecrets secrets = secretsByKeyId.get(siteKey);
    if (secrets == null) {
      return reject("unknown-key", action, null);
    }

    if (token == null || token.length() > MAX_TOKEN_LENGTH || !BASE64URL.matcher(token).matches()) {
      return reject("malformed", action, null);
    }

    final Altcha.Payload payload;
    final Altcha.VerifySolutionResult result;
    try {
      payload = Altcha.parsePayload(Base64.getEncoder().encodeToString(Base64.getUrlDecoder().decode(token)));
      result = Altcha.verifySolution(payload.challenge(), payload.solution(),
          secrets.signatureSecret(), secrets.keySignatureSecret(), Altcha.pbkdf2());
    } catch (final Exception e) {
      // 解不开的 base64 / JSON、控件的 test 模式（challenge 为 null）、非十六进制的派生结果……都算坏令牌
      return reject("malformed", action, null);
    }

    if (result.expired()) {
      return reject("expired", action, null);
    }
    if (!result.verified()) {
      return reject(Boolean.TRUE.equals(result.invalidSignature()) ? "bad-signature" : "bad-solution", action, null);
    }

    // 以下字段都在 HMAC 签名之内，客户端改不了
    final Altcha.ChallengeParameters parameters = payload.challenge().parameters();
    final Map<String, Object> data = parameters.data() != null ? parameters.data() : Map.of();
    final String tier = String.valueOf(data.get(DATA_TIER));

    final long nowSeconds = clock.instant().getEpochSecond();
    if (parameters.expiresAt() == null || parameters.expiresAt() < nowSeconds) {
      return reject("expired", action, tier);
    }
    if (!action.getActionName().equals(data.get(DATA_ACTION))) {
      return reject("action-mismatch", action, tier);
    }
    if (!siteKey.equals(data.get(DATA_KEY_ID))) {
      return reject("key-mismatch", action, tier);
    }

    // 一次性：同一个挑战（nonce）只能换一次；键活到挑战过期后 1 秒，过期的本来就会被上面拒掉
    final long ttlSeconds = parameters.expiresAt() - nowSeconds + 1;
    final String used = redisCluster.withCluster(connection -> connection.sync()
        .set(USED_NONCE_KEY_PREFIX + parameters.nonce(), "1", SetArgs.Builder.nx().ex(ttlSeconds)));
    if (!"OK".equals(used)) {
      return reject("replay", action, tier);
    }

    Metrics.counter(VERIFY_COUNTER_NAME, "outcome", "accepted", "action", action.getActionName(), "tier", tier)
        .increment();
    if (payload.solution().time() != null) {
      DistributionSummary.builder(SOLVE_MILLIS_NAME)
          .tags("action", action.getActionName(), "tier", tier)
          .publishPercentiles(0.5, 0.9, 0.99)
          .register(Metrics.globalRegistry)
          .record(Math.clamp(payload.solution().time(), 0L, 600_000L));
    }
    return AssessmentResult.fromScore(1.0f, 0.0f);
  }

  private static AssessmentResult reject(final String reason, final Action action, @Nullable final String tier) {
    logger.debug("ALTCHA token rejected: {}", reason);
    Metrics.counter(VERIFY_COUNTER_NAME,
            "outcome", reason,
            "action", action.getActionName(),
            "tier", tier != null ? tier : "unknown")
        .increment();
    return AssessmentResult.invalid();
  }

  /// 同一网段 / 全局，最近一小时（两个整点桶加权的滑动估计）签发了多少个挑战，含这一次
  private long countIssuance(final String counterName) {
    final long nowSeconds = clock.instant().getEpochSecond();
    final long window = nowSeconds / WINDOW_SECONDS;
    final double elapsedFraction = (double) (nowSeconds % WINDOW_SECONDS) / WINDOW_SECONDS;
    final String currentKey = COUNTER_KEY_PREFIX + counterName + "::" + window;
    final String previousKey = COUNTER_KEY_PREFIX + counterName + "::" + (window - 1);

    try {
      return redisCluster.withCluster(connection -> {
        final long current = connection.sync().incr(currentKey);
        connection.sync().expire(currentKey, 2 * WINDOW_SECONDS);
        final String previous = connection.sync().get(previousKey);
        final long previousCount = previous == null ? 0 : Long.parseLong(previous);
        return current + (long) Math.floor(previousCount * (1 - elapsedFraction));
      });
    } catch (final RuntimeException e) {
      logger.warn("Failed to count ALTCHA issuance; using the lowest tier", e);
      Metrics.counter(COUNTER_FAILURE_COUNTER_NAME).increment();
      return 0;
    }
  }

  private String segmentCounterName(@Nullable final String ip) {
    return "seg::" + HexFormat.of().formatHex(hmac(current.counterKey(), segmentOf(ip)), 0, 16);
  }

  /// 网段：IPv4 /24、IPv6 /56（§5.4）。解析不了的地址归到同一个 `unknown` 段
  @VisibleForTesting
  static String segmentOf(@Nullable final String ip) {
    if (ip == null || ip.isBlank()) {
      return "unknown";
    }
    try {
      final byte[] address = InetAddresses.forString(ip.strip()).getAddress();
      final int prefixBytes = address.length == 4 ? 3 : 7;
      for (int i = prefixBytes; i < address.length; i++) {
        address[i] = 0;
      }
      return InetAddresses.toAddrString(InetAddress.getByAddress(address)) + (address.length == 4 ? "/24" : "/56");
    } catch (final IllegalArgumentException | UnknownHostException e) {
      return "unknown";
    }
  }

  /// 网段计数 → 难度档：每越过一个阈值升一档；全局超预算再升一档；封顶最高档。**没有「拒绝」这个输出**
  @VisibleForTesting
  static int selectTier(final long segmentCount, final long globalCount, final List<Integer> segmentThresholds,
      final int globalHourlyBudget) {

    int tier = 0;
    for (final int threshold : segmentThresholds) {
      if (segmentCount > threshold) {
        tier++;
      }
    }
    if (globalCount > globalHourlyBudget) {
      tier++;
    }
    return Math.min(tier, segmentThresholds.size());
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
