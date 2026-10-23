/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.HttpHeaders;
import io.dropwizard.auth.Auth;
import io.micrometer.core.instrument.Metrics;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.NotFoundException;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.ServiceUnavailableException;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.asn.AsnInfo;
import org.whispersystems.textsecuregcm.asn.AsnInfoProvider;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.TellomiFeedTokens;
import org.whispersystems.textsecuregcm.filters.RemoteAddressFilter;
import org.whispersystems.textsecuregcm.limits.RateLimiter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.util.Util;

/// Tellomi（ADR-0071 §5.3、客户端接口契约第二节）：动态的内容引擎只认 Signal-Server 签的东西，
/// 这里用 Signal 账号鉴权签三种：
///
/// - `GET /v1/tellomi/feed/auth`：访问内容引擎的凭证（假名 + 内容区域，1 小时）；
/// - `POST|DELETE /v1/tellomi/feed/friend-assertions`：好友声明（5 分钟），客户端原样交给引擎，自己不接触别人的假名；
/// - `POST /v1/tellomi/feed/audience-lists`：「部分可见 / 不给谁看」名单（10 分钟）。
///
/// 好友关系在 Signal 里是端到端的（通讯录、消息请求都在手机上），服务端看不到。所以好友声明只证明「这一半是本人
/// 亲自报的」：引擎要两个人各自用自己的账号报一半才建边（数据模型 2.4），任何一方都没法替对方报。
@Path("/v1/tellomi/feed")
@Tag(name = "Tellomi")
public class TellomiFeedController {

  @VisibleForTesting
  static final Duration CREDENTIAL_LIFETIME = Duration.ofHours(1);
  @VisibleForTesting
  static final Duration FRIEND_ASSERTION_LIFETIME = Duration.ofMinutes(5);
  @VisibleForTesting
  static final Duration AUDIENCE_LIST_LIFETIME = Duration.ofMinutes(10);
  /// 引擎 `MaxAudienceMembers`
  public static final int MAX_AUDIENCE_MEMBERS = 500;

  /// 限流存储（Redis）不可用、限流器 fail closed 时给客户端的 `Retry-After`（秒）。
  @VisibleForTesting
  static final long LIMITER_UNAVAILABLE_RETRY_AFTER_SECONDS = 30;

  /// Body code of the 404 for "no account has that ACI" (friend-assertions). A 404 without it means "no such route".
  @VisibleForTesting
  static final String ERROR_ACCOUNT_NOT_FOUND = "account_not_found";

  static final String REGION_CN = "cn";
  static final String REGION_GLOBAL = "global";

  private static final Logger log = LoggerFactory.getLogger(TellomiFeedController.class);
  private static final String REGION_COUNTER_NAME = name(TellomiFeedController.class, "region");
  private static final String ASN_TABLE_EMPTY_COUNTER_NAME = name(TellomiFeedController.class, "asnTableEmpty");
  private static final String DEGRADED_LIMIT_COUNTER_NAME = name(TellomiFeedController.class, "degradedIpLimit");
  private static final String LIMITER_UNAVAILABLE_COUNTER_NAME = name(TellomiFeedController.class, "limiterUnavailable");
  private static final String UNKNOWN_REMOTE_ADDRESS = "unknown";
  private static final String VIA_NUMBER = "number";
  private static final String VIA_HOST = "host";
  private static final String VIA_ASN = "asn";
  private static final String VIA_DEFAULT = "default";

  private static final String CN_COUNTRY_CODE = "86";
  private static final String X_FORWARDED_HOST = "X-Forwarded-Host";

  private final AccountsManager accountsManager;
  private final RateLimiters rateLimiters;
  private final TellomiFeedTokens tokens;
  private final List<String> cnHostSuffixes;
  private final Supplier<AsnInfoProvider> asnInfoProviderSupplier;
  private final Clock clock;
  private final AtomicBoolean asnTableEmptyLogged = new AtomicBoolean();

  public TellomiFeedController(final AccountsManager accountsManager,
      final RateLimiters rateLimiters,
      final TellomiFeedTokens tokens,
      final List<String> cnHostSuffixes,
      final Supplier<AsnInfoProvider> asnInfoProviderSupplier,
      final Clock clock) {

    this.accountsManager = accountsManager;
    this.rateLimiters = rateLimiters;
    this.tokens = tokens;
    this.cnHostSuffixes = List.copyOf(cnHostSuffixes);
    this.asnInfoProviderSupplier = asnInfoProviderSupplier;
    this.clock = clock;
  }

  public record FeedCredential(String token, @JsonProperty("expires_at") String expiresAt, String region) {
  }

  public record FriendAssertionRequest(@NotBlank @JsonProperty("peer_aci") String peerAci) {
  }

  public record FriendAssertion(String assertion) {
  }

  /// `{"error": "<code>"}`, the same shape the content engine uses for its errors.
  public record FeedError(String error) {
  }

  public record AudienceListRequest(@NotNull @Pattern(regexp = "include|exclude") String kind,
                                    @NotEmpty @Size(max = MAX_AUDIENCE_MEMBERS)
                                    @JsonProperty("peer_acis") List<@NotBlank String> peerAcis) {
  }

  public record AudienceList(@JsonProperty("audience_token") String audienceToken) {
  }

  @GET
  @Path("/auth")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Issues a credential for the Tellomi content engine",
      description = """
          Returns a short-lived HS256 JWT carrying the caller's derived pseudonym and content region (`cn` or `global`).
          The region is computed by the server, strictest first: a +86 number, then a mainland entry host or address.
          """)
  @ApiResponse(responseCode = "200", description = "The credential", useReturnTypeSchema = true)
  @ApiResponse(responseCode = "401", description = "Account authentication check failed")
  @ApiResponse(responseCode = "429", description = "Too many credential requests from this account. Retry-After (whole seconds) says when to retry")
  @ApiResponse(responseCode = "503", description = "The rate limiter's store is unavailable. Retry-After says when to retry")
  public FeedCredential getCredential(@Auth final AuthenticatedDevice auth,
      @Context final ContainerRequestContext requestContext) throws RateLimitExceededException {

    // 审计 SF-4：按账号限流，防出错的客户端死循环反复取（凭证本身只是一次便宜的 HMAC，没有存在性探测，限流器挂了就放行）。
    // 先限流再查账号。这里不加按 IP 的一层：和好友声明不同，这个接口没有放大（一次一个 HMAC）。
    validateAccount("auth", rateLimiters.getTellomiFeedAuthLimiter(), auth.accountIdentifier());

    final Account account = accountsManager.getByAccountIdentifier(auth.accountIdentifier())
        .orElseThrow(() -> new WebApplicationException(Response.Status.UNAUTHORIZED));

    final String region = region(account, requestContext);
    // Whole seconds, like the token's `exp`: Instant.toString() would otherwise print the clock's nanoseconds
    // ("...12:00:00.654809212Z"), which the contract's example ("...12:00:00Z") and strict ISO-8601 parsers
    // on the clients do not expect.
    final Instant expiration = clock.instant().plus(CREDENTIAL_LIFETIME).truncatedTo(ChronoUnit.SECONDS);
    return new FeedCredential(tokens.credential(auth.accountIdentifier(), region, expiration),
        expiration.toString(), region);
  }

  @POST
  @Path("/friend-assertions")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Signs the caller's half of a Tellomi friendship",
      description = """
          Signs "the caller considers `peer_aci` a friend" for the content engine. The engine links two people only
          after both have submitted their own half.
          """)
  @ApiResponse(responseCode = "200", description = "The signed assertion", useReturnTypeSchema = true)
  @ApiResponse(responseCode = "400", description = "`peer_aci` is not an ACI, or is the caller")
  @ApiResponse(responseCode = "404", description = "No account has that ACI. The body is `{\"error\":\"account_not_found\"}`; a 404 without it means the route is not available on this server")
  @ApiResponse(responseCode = "429", description = "Too many friend assertions from this account (or, while the ASN table is empty, from this address)")
  @ApiResponse(responseCode = "503", description = "The rate limiter's store is unavailable; nothing was signed. Retry-After says when to retry")
  public FriendAssertion addFriend(@Auth final AuthenticatedDevice auth,
      @NotNull @Valid final FriendAssertionRequest request,
      @Context final ContainerRequestContext requestContext) throws RateLimitExceededException {

    // 先限流、再解析和查账号：这个接口的 404 / 200 能让人探测某个 ACI 有没有账号（PR #13 的欠账），格式错的请求也占一个名额。
    // ASN 表是空的时候多限一层按来源 IP 的（见 validateIpWhileAsnTableIsEmpty）
    validateIpWhileAsnTableIsEmpty("friendAssertion", rateLimiters::getTellomiFeedFriendAssertionIpLimiter, requestContext);
    validateAccount("friendAssertion", rateLimiters.getTellomiFeedFriendAssertionLimiter(), auth.accountIdentifier());

    final UUID peer = peer(auth, request.peerAci());
    if (accountsManager.getByAccountIdentifier(peer).isEmpty()) {
      // 带标记的 404：没有标记的 404 只可能是「这台服务器没有这条路由」（没配 tellomiFeed:），客户端据此区分，
      // 见 FRIEND-ASSERTION-404-MARKER.md。其它状态码不变。
      throw new NotFoundException(Response.status(Response.Status.NOT_FOUND)
          .type(MediaType.APPLICATION_JSON_TYPE)
          .entity(new FeedError(ERROR_ACCOUNT_NOT_FOUND))
          .build());
    }
    return new FriendAssertion(tokens.friendAssertion(auth.accountIdentifier(), peer, "add",
        clock.instant().plus(FRIEND_ASSERTION_LIFETIME)));
  }

  @DELETE
  @Path("/friend-assertions/{peerAci}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Signs the withdrawal of a Tellomi friendship",
      description = "Works whether or not the peer's account still exists; the engine drops the whole link.")
  @ApiResponse(responseCode = "200", description = "The signed assertion", useReturnTypeSchema = true)
  @ApiResponse(responseCode = "400", description = "`peerAci` is not an ACI, or is the caller")
  @ApiResponse(responseCode = "429", description = "Too many friend assertions from this account (shared with POST /friend-assertions)")
  @ApiResponse(responseCode = "503", description = "The rate limiter's store is unavailable; nothing was signed. Retry-After says when to retry")
  public FriendAssertion removeFriend(@Auth final AuthenticatedDevice auth,
      @Parameter(description = "The friend's ACI") @PathParam("peerAci") final String peerAci)
      throws RateLimitExceededException {

    // 和 POST 共用同一个按账号的 tellomiFeedFriendAssertion 桶（600，每 6 秒补 1）：不查账号、没有探测问题，只防刷签名。
    // 先限流再解析，格式错的请求也占名额（和 POST 一样）。
    validateAccount("friendAssertionRemove", rateLimiters.getTellomiFeedFriendAssertionLimiter(), auth.accountIdentifier());

    final UUID peer = peer(auth, peerAci);
    return new FriendAssertion(tokens.friendAssertion(auth.accountIdentifier(), peer, "remove",
        clock.instant().plus(FRIEND_ASSERTION_LIFETIME)));
  }

  @POST
  @Path("/audience-lists")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Signs a post's audience list for the Tellomi content engine",
      description = """
          Signs the caller's "only these people" (`include`) or "everyone but these people" (`exclude`) list as
          pseudonyms. Duplicates and the caller are dropped; at most 500 people.
          """)
  @ApiResponse(responseCode = "200", description = "The signed list", useReturnTypeSchema = true)
  @ApiResponse(responseCode = "400", description = "An entry is not an ACI, or no one is left besides the caller")
  @ApiResponse(responseCode = "422", description = "Bad `kind`, or the list is empty or too long")
  @ApiResponse(responseCode = "429", description = "Too many audience lists from this account (or, while the ASN table is empty, from this address)")
  @ApiResponse(responseCode = "503", description = "The rate limiter's store is unavailable; nothing was signed. Retry-After says when to retry")
  public AudienceList signAudienceList(@Auth final AuthenticatedDevice auth,
      @NotNull @Valid final AudienceListRequest request,
      @Context final ContainerRequestContext requestContext) throws RateLimitExceededException {

    validateIpWhileAsnTableIsEmpty("audienceList", rateLimiters::getTellomiFeedAudienceListIpLimiter, requestContext);
    validateAccount("audienceList", rateLimiters.getTellomiFeedAudienceListLimiter(), auth.accountIdentifier());

    final Set<UUID> members = new LinkedHashSet<>();
    for (final String aci : request.peerAcis()) {
      members.add(parseAci(aci));
    }
    members.remove(auth.accountIdentifier());
    if (members.isEmpty()) {
      throw new BadRequestException();
    }
    return new AudienceList(tokens.audienceList(auth.accountIdentifier(), request.kind(), List.copyOf(members),
        clock.instant().plus(AUDIENCE_LIST_LIFETIME)));
  }

  /// 内容区域（ADR-0071 §5.3「取严」）：+86 号码 → cn；否则经大陆入口（`tellomi.cn` 主机）或大陆 IP 进来 → cn；都不是才 global
  @VisibleForTesting
  String region(final Account account, final ContainerRequestContext requestContext) {
    final String via;
    if (account.getNumber().map(Util::getCountryCode).filter(CN_COUNTRY_CODE::equals).isPresent()) {
      via = VIA_NUMBER;
    } else if (isCnHost(requestContext.getHeaderString(HttpHeaders.HOST))
        || isCnHost(requestContext.getHeaderString(X_FORWARDED_HOST))) {
      via = VIA_HOST;
    } else if (isCnAddress((String) requestContext.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME))) {
      via = VIA_ASN;
    } else {
      via = VIA_DEFAULT;
    }
    final String region = VIA_DEFAULT.equals(via) ? REGION_GLOBAL : REGION_CN;
    Metrics.counter(REGION_COUNTER_NAME, "region", region, "via", via).increment();
    return region;
  }

  /// ASN 表判定的大陆 IP。表是 S3 上的 iptoasn TSV，由 `asnTable` 配置的监视器载入；还没载入（或载入失败）时提供者是
  /// `AsnInfoProvider.EMPTY`，载入的是个空表时（香港目前指向一个空的 gzip）提供者里一条都没有——两种都是
  /// `AsnInfoProvider.isEmpty()`，这一项就永远判不出 CN（PR #13 的欠账）。区域的判定不改（仍按 global，改成 cn 是产品决定），
  /// 但它是可见的（计数器 `asnTableEmpty` + 一条 WARN），并且这时好友声明和受众名单接口会多限一层按 IP 的
  /// （见 `validateIpWhileAsnTableIsEmpty`）。
  private boolean isCnAddress(@Nullable final String remoteAddress) {
    if (remoteAddress == null) {
      return false;
    }
    final AsnInfoProvider provider = asnInfoProviderSupplier.get();
    if (provider.isEmpty()) {
      noteAsnTableEmpty();
      return false;
    }
    return provider.lookup(remoteAddress)
        .map(AsnInfo::regionCode)
        .filter("CN"::equalsIgnoreCase)
        .isPresent();
  }

  /// 每个不得不依赖空 ASN 表的决定（区域判定、按 IP 限流）加一次计数，第一次写一条 WARN。
  private void noteAsnTableEmpty() {
    Metrics.counter(ASN_TABLE_EMPTY_COUNTER_NAME).increment();
    if (asnTableEmptyLogged.compareAndSet(false, true)) {
      log.warn("Tellomi feed: the ASN table is empty (not loaded yet, its S3 object failed to load, or the object has no rows); "
          + "mainland IP detection is inactive (only +86 numbers and mainland entry hosts select region cn) "
          + "and friend-assertion / audience-list requests are rate limited per account AND per source address");
    }
  }

  /// 降级策略（B-9）：ASN 表是空的时，认不出大陆 IP，不能默认放行，所以在按账号限流之外再加一层按来源 IP 的限流。
  /// 表载入后这里什么都不做，行为和只有按账号一层时完全一样。拿不到来源地址时用共享的 "unknown" 键（过滤器正常都会设，
  /// 这是保守的兜底：宁可一起限，也不放行）。
  private void validateIpWhileAsnTableIsEmpty(final String endpoint, final Supplier<RateLimiter> ipLimiter,
      final ContainerRequestContext requestContext) throws RateLimitExceededException {

    if (!asnInfoProviderSupplier.get().isEmpty()) {
      return;
    }
    noteAsnTableEmpty();
    Metrics.counter(DEGRADED_LIMIT_COUNTER_NAME, "endpoint", endpoint).increment();
    final String remoteAddress = (String) requestContext.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME);
    final String key = remoteAddress == null ? UNKNOWN_REMOTE_ADDRESS : remoteAddress;
    failClosedAsUnavailable(endpoint, () -> ipLimiter.get().validate(key));
  }

  private void validateAccount(final String endpoint, final RateLimiter limiter, final UUID accountIdentifier)
      throws RateLimitExceededException {

    failClosedAsUnavailable(endpoint, () -> limiter.validate(accountIdentifier));
  }

  @FunctionalInterface
  private interface LimiterCall {
    void run() throws RateLimitExceededException;
  }

  /// 限流器自己出错（Redis 不可用；`failOpen = false` 的限流器会把存储抛出的运行时异常原样抛出来）：仍然拒绝（不签名、
  /// 不查账号），但回 503 + `Retry-After`，而不是一个没有任何线索的 500。真的超限（`RateLimitExceededException`）照旧是 429。
  private void failClosedAsUnavailable(final String endpoint, final LimiterCall call) throws RateLimitExceededException {
    try {
      call.run();
    } catch (final RateLimitExceededException e) {
      throw e;
    } catch (final RuntimeException e) {
      log.warn("Tellomi feed: rate limiter for {} failed, answering 503", endpoint, e);
      Metrics.counter(LIMITER_UNAVAILABLE_COUNTER_NAME, "endpoint", endpoint).increment();
      throw new ServiceUnavailableException(LIMITER_UNAVAILABLE_RETRY_AFTER_SECONDS);
    }
  }

  private boolean isCnHost(@Nullable final String hostHeader) {
    if (hostHeader == null || hostHeader.isBlank()) {
      return false;
    }
    // X-Forwarded-Host 可能是逗号分隔的一串；任何一跳是大陆入口都算
    for (final String entry : hostHeader.split(",")) {
      String host = entry.trim().toLowerCase(Locale.ROOT);
      final int colon = host.lastIndexOf(':');
      if (colon > 0 && host.indexOf(']') < colon) {
        host = host.substring(0, colon);
      }
      if (host.endsWith(".")) {
        host = host.substring(0, host.length() - 1);
      }
      for (final String suffix : cnHostSuffixes) {
        if (host.equals(suffix) || host.endsWith("." + suffix)) {
          return true;
        }
      }
    }
    return false;
  }

  private static UUID peer(final AuthenticatedDevice auth, final String peerAci) {
    final UUID peer = parseAci(peerAci);
    if (peer.equals(auth.accountIdentifier())) {
      throw new BadRequestException();
    }
    return peer;
  }

  private static UUID parseAci(@Nullable final String aci) {
    final String s = Optional.ofNullable(aci).orElse("").trim();
    // UUID.fromString 也收「1-1-1-1-1」这种短写；只认标准 36 位
    if (s.length() != 36) {
      throw new BadRequestException();
    }
    try {
      return UUID.fromString(s);
    } catch (final IllegalArgumentException e) {
      throw new BadRequestException();
    }
  }
}
