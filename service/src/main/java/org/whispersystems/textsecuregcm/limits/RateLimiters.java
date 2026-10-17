/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.limits;

import com.google.common.annotations.VisibleForTesting;
import java.time.Clock;
import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import io.dropwizard.util.DataSize;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.redis.ClusterLuaScript;
import org.whispersystems.textsecuregcm.redis.FaultTolerantRedisClusterClient;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;

public class RateLimiters extends BaseRateLimiters<RateLimiters.For> {

  public enum For implements RateLimiterDescriptor {
    BACKUP_AUTH_CHECK("backupAuthCheck", new RateLimiterConfig(100, Duration.ofMinutes(15), true)),
    PIN("pin", new RateLimiterConfig(10, Duration.ofDays(1), false)),
    ATTACHMENT("attachmentCreate", new RateLimiterConfig(50, Duration.ofMillis(1200), true)),
    ATTACHMENT_BYTES("attachmentCreateBytes", new RateLimiterConfig(DataSize.gigabytes(1).toBytes(), Duration.ofNanos(1000), true)),
    BACKUP_ATTACHMENT("backupAttachmentCreate", new RateLimiterConfig(10_000, Duration.ofSeconds(1), true)),
    PRE_KEYS("prekeys", new RateLimiterConfig(6, Duration.ofMinutes(10), false)),
    MESSAGES("messages", new RateLimiterConfig(60, Duration.ofSeconds(1), true)),
    STORIES("stories", new RateLimiterConfig(5_000, Duration.ofSeconds(8), true)),
    ALLOCATE_DEVICE("allocateDevice", new RateLimiterConfig(6, Duration.ofMinutes(2), false)),
    VERIFY_DEVICE("verifyDevice", new RateLimiterConfig(6, Duration.ofMinutes(2), false)),
    PROFILE("profile", new RateLimiterConfig(4320, Duration.ofSeconds(20), true)),
    PROFILE_AVATAR_BYTES("profileAvatarBytes", new RateLimiterConfig(DataSize.mebibytes(100).toBytes(), Duration.ofNanos(10000), true)),
    STICKER_PACK("stickerPack", new RateLimiterConfig(50, Duration.ofMinutes(72), false)),
    USERNAME_LOOKUP("usernameLookup", new RateLimiterConfig(100, Duration.ofMinutes(15), true)),
    USERNAME_SET("usernameSet", new RateLimiterConfig(100, Duration.ofMinutes(15), false)),
    USERNAME_RESERVE("usernameReserve", new RateLimiterConfig(100, Duration.ofMinutes(15), false)),
    USERNAME_LINK_OPERATION("usernameLinkOperation", new RateLimiterConfig(10, Duration.ofMinutes(1), false)),
    USERNAME_LINK_LOOKUP_PER_IP("usernameLinkLookupPerIp", new RateLimiterConfig(100, Duration.ofSeconds(15), true)),
    CHECK_ACCOUNT_EXISTENCE("checkAccountExistence", new RateLimiterConfig(1000, Duration.ofSeconds(4), true)),
    REGISTRATION("registration", new RateLimiterConfig(6, Duration.ofSeconds(30), false)),
    SET_ZK_CREDENTIAL_KEY("setZkCredentialKey", new RateLimiterConfig(5, Duration.ofDays(7), false)),
    VERIFICATION_PUSH_CHALLENGE("verificationPushChallenge", new RateLimiterConfig(5, Duration.ofSeconds(30), false)),
    VERIFICATION_CAPTCHA("verificationCaptcha", new RateLimiterConfig(10, Duration.ofSeconds(30), false)),
    RATE_LIMIT_RESET("rateLimitReset", new RateLimiterConfig(2, Duration.ofHours(12), false)),
    CAPTCHA_CHALLENGE_ATTEMPT("captchaChallengeAttempt", new RateLimiterConfig(10, Duration.ofMinutes(144), false)),
    CAPTCHA_CHALLENGE_SUCCESS("captchaChallengeSuccess", new RateLimiterConfig(2, Duration.ofHours(12), false)),
    SET_BACKUP_ID("setBackupId", new RateLimiterConfig(10, Duration.ofHours(1), false)),
    SET_PAID_MEDIA_BACKUP_ID("setPaidMediaBackupId", new RateLimiterConfig(5, Duration.ofDays(7), false)),
    PUSH_CHALLENGE_ATTEMPT("pushChallengeAttempt", new RateLimiterConfig(10, Duration.ofMinutes(144), false)),
    PUSH_CHALLENGE_SUCCESS("pushChallengeSuccess", new RateLimiterConfig(2, Duration.ofHours(12), false)),
    GET_CALLING_RELAYS("getCallingRelays", new RateLimiterConfig(100, Duration.ofMinutes(10), false)),
    CREATE_CALL_LINK("createCallLink", new RateLimiterConfig(100, Duration.ofMinutes(15), false)),
    INBOUND_MESSAGE_BYTES("inboundMessageBytes", new RateLimiterConfig(128 * 1024 * 1024, Duration.ofNanos(500_000), true)),
    EXTERNAL_SERVICE_CREDENTIALS("externalServiceCredentials", new RateLimiterConfig(100, Duration.ofMinutes(15), false)),
    KEY_TRANSPARENCY_DISTINGUISHED_PER_IP("keyTransparencyDistinguished", new RateLimiterConfig(100, Duration.ofSeconds(15), true)),
    KEY_TRANSPARENCY_SEARCH_PER_IP("keyTransparencySearch", new RateLimiterConfig(100, Duration.ofSeconds(15), true)),
    KEY_TRANSPARENCY_MONITOR_PER_IP("keyTransparencyMonitor", new RateLimiterConfig(100, Duration.ofSeconds(15), true)),
    WAIT_FOR_LINKED_DEVICE("waitForLinkedDevice", new RateLimiterConfig(10, Duration.ofSeconds(30), false)),
    UPLOAD_TRANSFER_ARCHIVE("uploadTransferArchive", new RateLimiterConfig(10, Duration.ofMinutes(1), false)),
    WAIT_FOR_TRANSFER_ARCHIVE("waitForTransferArchive", new RateLimiterConfig(10, Duration.ofSeconds(30), false)),
    RECORD_DEVICE_TRANSFER_REQUEST("recordDeviceTransferRequest", new RateLimiterConfig(10, Duration.ofMillis(100), true)),
    WAIT_FOR_DEVICE_TRANSFER_REQUEST("waitForDeviceTransferRequest", new RateLimiterConfig(10, Duration.ofMillis(100), true)),
    DEVICE_CHECK_CHALLENGE("deviceCheckChallenge", new RateLimiterConfig(10, Duration.ofMinutes(1), false)),
    SUBMIT_CALL_QUALITY_SURVEY("submitCallQualitySurvey", new RateLimiterConfig(100, Duration.ofMinutes(1), true)),
    BATCH_IDENTITY_CHECK("batchIdentityCheck", new RateLimiterConfig(100, Duration.ofMinutes(1), true)),
    CREATE_DONATION_PERMIT("createDonationCredential", new RateLimiterConfig(30, Duration.ofHours(4), true)),
    ONE_TIME_DONATION("oneTimeDonation", new RateLimiterConfig(5, Duration.ofMinutes(1), true)),
    ADD_SUBSCRIPTION_PAYMENT_METHOD("addSubscriptionPaymentMethod", new RateLimiterConfig(10, Duration.ofMinutes(1), true)),
    CHECK_MFA("checkMfa", new RateLimiterConfig(50, Duration.ofHours(12), false)),
    // Tellomi（ADR-0071 §5.3，B-9）：POST /v1/tellomi/feed/friend-assertions。按调用者账号计；它能探测某个 ACI 有没有账号
    // （404 / 200），所以 Redis 不可用时拒绝（failOpen = false）。首次同步最多约 500 个好友，所以桶是 600，之后每 6 秒回一个
    // （一小时约 600 次）。运行时可以用动态配置 limits.tellomiFeedFriendAssertion 调。
    TELLOMI_FEED_FRIEND_ASSERTION("tellomiFeedFriendAssertion", new RateLimiterConfig(600, Duration.ofSeconds(6), false)),
    // Tellomi：POST /v1/tellomi/feed/audience-lists。按调用者账号计；不查账号是否存在，没有探测问题，只防刷（每次最多
    // 500 人要算 HMAC），Redis 不可用时放行。一个人短时间最多发 60 条「部分可见」帖子，之后每 20 秒回一个。
    TELLOMI_FEED_AUDIENCE_LIST("tellomiFeedAudienceList", new RateLimiterConfig(60, Duration.ofSeconds(20), true)),
    // Tellomi：ASN 表是空的（没载入 / 载入失败）时的第二层——按来源 IP 计。表空时认不出大陆 IP，区域一律按 global，
    // 光靠按账号的限流不够（一个 IP 后面可以有很多账号），所以这时两个接口再按 IP 限一层。表载入后不用这两个。
    // 比按账号的宽一倍（运营商级 NAT 后面会有很多正常用户）；失败策略和按账号的一致。动态配置同样能调。
    TELLOMI_FEED_FRIEND_ASSERTION_IP("tellomiFeedFriendAssertionIp", new RateLimiterConfig(1200, Duration.ofSeconds(3), false)),
    TELLOMI_FEED_AUDIENCE_LIST_IP("tellomiFeedAudienceListIp", new RateLimiterConfig(120, Duration.ofSeconds(10), true)),
    // Tellomi（tellomi/tellomi#1368，ADR-0078 §3.1 第 3 条）：举报垃圾消息（HTTP POST /v1/messages/report、gRPC reportMessage），
    // 按举报人账号计。上游这个接口没有任何限流。客户端一次举报最多报 3 条消息（= 3 次调用），桶 30 ≈ 连着举报 10 次，
    // 之后每 48 分钟回一个（一天约 30 次）。只防刷，不探测任何东西，Redis 不可用时放行。动态配置 limits.tellomiReportSpam 可调。
    TELLOMI_REPORT_SPAM("tellomiReportSpam", new RateLimiterConfig(30, Duration.ofMinutes(48), true)),
    // Tellomi（审计 SF-4）：GET /v1/tellomi/feed/auth。按调用者账号计。客户端把凭证缓存到 `expires_at` 前 5 分钟，正常一个设备
    // 一小时取一次；这里只防「出错的客户端死循环反复取」。接口只是一次便宜的 HMAC、没有账号存在性探测，所以 Redis 不可用时
    // 放行（failOpen = true，不能因为限流器挂了让所有人拿不到动态凭证）。桶 60、每 1 分钟回一个（一小时约 60 次，
    // 足够多设备、重装、重试）。运行时可以用动态配置 limits.tellomiFeedAuth 调。
    TELLOMI_FEED_AUTH("tellomiFeedAuth", new RateLimiterConfig(60, Duration.ofMinutes(1), true))
    ;

    private final String id;

    private final RateLimiterConfig defaultConfig;

    For(final String id, final RateLimiterConfig defaultConfig) {
      this.id = id;
      this.defaultConfig = defaultConfig;
    }

    public String id() {
      return id;
    }

    public RateLimiterConfig defaultConfig() {
      return defaultConfig;
    }
  }

  public static RateLimiters create(
      final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager,
      final FaultTolerantRedisClusterClient cacheCluster,
      final ScheduledExecutorService retryExecutor) {
    return new RateLimiters(
        dynamicConfigurationManager, defaultScript(cacheCluster), cacheCluster, retryExecutor, Clock.systemUTC());
  }

  @VisibleForTesting
  RateLimiters(
      final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager,
      final ClusterLuaScript validateScript,
      final FaultTolerantRedisClusterClient cacheCluster,
      final ScheduledExecutorService retryExecutor,
      final Clock clock) {
    super(For.values(), dynamicConfigurationManager, validateScript, cacheCluster, retryExecutor, clock);
  }

  public RateLimiter getAllocateDeviceLimiter() {
    return forDescriptor(For.ALLOCATE_DEVICE);
  }

  public RateLimiter getVerifyDeviceLimiter() {
    return forDescriptor(For.VERIFY_DEVICE);
  }

  public RateLimiter getSetZkCredentialKeyLimiter() {
    return forDescriptor(For.SET_ZK_CREDENTIAL_KEY);
  }

  public RateLimiter getPreKeysLimiter() {
    return forDescriptor(For.PRE_KEYS);
  }

  public RateLimiter getAttachmentLimiter() {
    return forDescriptor(For.ATTACHMENT);
  }

  public RateLimiter getAttachmentBytesLimiter() {
    return forDescriptor(For.ATTACHMENT_BYTES);
  }

  public RateLimiter getPinLimiter() {
    return forDescriptor(For.PIN);
  }

  public RateLimiter getProfileLimiter() {
    return forDescriptor(For.PROFILE);
  }

  public RateLimiter getProfileAvatarBytesLimiter() {
    return forDescriptor(For.PROFILE_AVATAR_BYTES);
  }

  public RateLimiter getStickerPackLimiter() {
    return forDescriptor(For.STICKER_PACK);
  }

  public RateLimiter getUsernameLookupLimiter() {
    return forDescriptor(For.USERNAME_LOOKUP);
  }

  public RateLimiter getUsernameLinkLookupLimiter() {
    return forDescriptor(For.USERNAME_LINK_LOOKUP_PER_IP);
  }

  public RateLimiter getUsernameLinkOperationLimiter() {
    return forDescriptor(For.USERNAME_LINK_OPERATION);
  }

  public RateLimiter getUsernameSetLimiter() {
    return forDescriptor(For.USERNAME_SET);
  }

  public RateLimiter getUsernameReserveLimiter() {
    return forDescriptor(For.USERNAME_RESERVE);
  }

  public RateLimiter getCheckAccountExistenceLimiter() {
    return forDescriptor(For.CHECK_ACCOUNT_EXISTENCE);
  }

  public RateLimiter getRegistrationLimiter() {
    return forDescriptor(For.REGISTRATION);
  }

  public RateLimiter getMessagesLimiter() {
    return forDescriptor(For.MESSAGES);
  }

  public RateLimiter getRateLimitResetLimiter() {
    return forDescriptor(For.RATE_LIMIT_RESET);
  }

  public RateLimiter getCaptchaChallengeAttemptLimiter() {
    return forDescriptor(For.CAPTCHA_CHALLENGE_ATTEMPT);
  }

  public RateLimiter getCaptchaChallengeSuccessLimiter() {
    return forDescriptor(For.CAPTCHA_CHALLENGE_SUCCESS);
  }

  public RateLimiter getPushChallengeAttemptLimiter() {
    return forDescriptor(For.PUSH_CHALLENGE_ATTEMPT);
  }

  public RateLimiter getPushChallengeSuccessLimiter() {
    return forDescriptor(For.PUSH_CHALLENGE_SUCCESS);
  }

  public RateLimiter getVerificationPushChallengeLimiter() {
    return forDescriptor(For.VERIFICATION_PUSH_CHALLENGE);
  }

  public RateLimiter getVerificationCaptchaLimiter() {
    return forDescriptor(For.VERIFICATION_CAPTCHA);
  }

  public RateLimiter getCreateCallLinkLimiter() {
    return forDescriptor(For.CREATE_CALL_LINK);
  }

  public RateLimiter getCallEndpointLimiter() {
    return forDescriptor(For.GET_CALLING_RELAYS);
  }

  public RateLimiter getInboundMessageBytes() {
    return forDescriptor(For.INBOUND_MESSAGE_BYTES);
  }

  public RateLimiter getStoriesLimiter() {
    return forDescriptor(For.STORIES);
  }

  public RateLimiter getWaitForLinkedDeviceLimiter() {
    return forDescriptor(For.WAIT_FOR_LINKED_DEVICE);
  }

  public RateLimiter getUploadTransferArchiveLimiter() {
    return forDescriptor(For.UPLOAD_TRANSFER_ARCHIVE);
  }

  public RateLimiter getWaitForTransferArchiveLimiter() {
    return forDescriptor(For.WAIT_FOR_TRANSFER_ARCHIVE);
  }

  public RateLimiter getKeyTransparencySearchLimiter() {
    return forDescriptor(For.KEY_TRANSPARENCY_SEARCH_PER_IP);
  }

  public RateLimiter getKeyTransparencyDistinguishedLimiter() {
    return forDescriptor(For.KEY_TRANSPARENCY_DISTINGUISHED_PER_IP);
  }

  public RateLimiter getKeyTransparencyMonitorLimiter() {
    return forDescriptor(For.KEY_TRANSPARENCY_MONITOR_PER_IP);
  }

  public RateLimiter getSubmitCallQualitySurveyLimiter() {
    return forDescriptor(For.SUBMIT_CALL_QUALITY_SURVEY);
  }

  public RateLimiter getCreateDonationPermitLimiter() {
    return forDescriptor(For.CREATE_DONATION_PERMIT);
  }

  public RateLimiter getCheckMfaLimiter() {
    return forDescriptor(For.CHECK_MFA);
  }

  public RateLimiter getTellomiFeedFriendAssertionLimiter() {
    return forDescriptor(For.TELLOMI_FEED_FRIEND_ASSERTION);
  }

  public RateLimiter getTellomiFeedAudienceListLimiter() {
    return forDescriptor(For.TELLOMI_FEED_AUDIENCE_LIST);
  }

  public RateLimiter getTellomiFeedAuthLimiter() {
    return forDescriptor(For.TELLOMI_FEED_AUTH);
  }

  public RateLimiter getTellomiFeedFriendAssertionIpLimiter() {
    return forDescriptor(For.TELLOMI_FEED_FRIEND_ASSERTION_IP);
  }

  public RateLimiter getTellomiFeedAudienceListIpLimiter() {
    return forDescriptor(For.TELLOMI_FEED_AUDIENCE_LIST_IP);
  }

  public RateLimiter getTellomiReportSpamLimiter() {
    return forDescriptor(For.TELLOMI_REPORT_SPAM);
  }
}
