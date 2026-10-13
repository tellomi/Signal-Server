/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.HttpHeaders;
import io.dropwizard.auth.Auth;
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
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Supplier;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.asn.AsnInfo;
import org.whispersystems.textsecuregcm.asn.AsnInfoProvider;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.auth.TellomiFeedTokens;
import org.whispersystems.textsecuregcm.filters.RemoteAddressFilter;
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

  static final String REGION_CN = "cn";
  static final String REGION_GLOBAL = "global";

  private static final String CN_COUNTRY_CODE = "86";
  private static final String X_FORWARDED_HOST = "X-Forwarded-Host";

  private final AccountsManager accountsManager;
  private final TellomiFeedTokens tokens;
  private final List<String> cnHostSuffixes;
  private final Supplier<AsnInfoProvider> asnInfoProviderSupplier;
  private final Clock clock;

  public TellomiFeedController(final AccountsManager accountsManager,
      final TellomiFeedTokens tokens,
      final List<String> cnHostSuffixes,
      final Supplier<AsnInfoProvider> asnInfoProviderSupplier,
      final Clock clock) {

    this.accountsManager = accountsManager;
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
  public FeedCredential getCredential(@Auth final AuthenticatedDevice auth,
      @Context final ContainerRequestContext requestContext) {

    final Account account = accountsManager.getByAccountIdentifier(auth.accountIdentifier())
        .orElseThrow(() -> new WebApplicationException(Response.Status.UNAUTHORIZED));

    final String region = region(account, requestContext);
    final Instant expiration = clock.instant().plus(CREDENTIAL_LIFETIME);
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
  @ApiResponse(responseCode = "404", description = "No account has that ACI")
  public FriendAssertion addFriend(@Auth final AuthenticatedDevice auth,
      @NotNull @Valid final FriendAssertionRequest request) {

    final UUID peer = peer(auth, request.peerAci());
    if (accountsManager.getByAccountIdentifier(peer).isEmpty()) {
      throw new NotFoundException();
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
  public FriendAssertion removeFriend(@Auth final AuthenticatedDevice auth,
      @Parameter(description = "The friend's ACI") @PathParam("peerAci") final String peerAci) {

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
  public AudienceList signAudienceList(@Auth final AuthenticatedDevice auth,
      @NotNull @Valid final AudienceListRequest request) {

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
    if (account.getNumber().map(Util::getCountryCode).filter(CN_COUNTRY_CODE::equals).isPresent()) {
      return REGION_CN;
    }
    if (isCnHost(requestContext.getHeaderString(HttpHeaders.HOST))
        || isCnHost(requestContext.getHeaderString(X_FORWARDED_HOST))) {
      return REGION_CN;
    }
    final String remoteAddress = (String) requestContext.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME);
    if (remoteAddress != null && asnInfoProviderSupplier.get().lookup(remoteAddress)
        .map(AsnInfo::regionCode)
        .filter("CN"::equalsIgnoreCase)
        .isPresent()) {
      return REGION_CN;
    }
    return REGION_GLOBAL;
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
