/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.grpc.Status;
import io.micrometer.core.instrument.Metrics;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.whispersystems.textsecuregcm.identity.ServiceIdentifier;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions.Restriction;

/// Tellomi（ADR-0078 §3.3 第二刀，tellomi/tellomi#1368）：被处置的账号不能再用非密封发送给别人发消息。
///
/// 非密封发送（`INDIVIDUAL_IDENTIFIED_SENDER`）是没有对方资料密钥时的发法——给陌生人的第一条消息、消息请求都是它，
/// 也就是垃圾消息的来路。互相交换过资料密钥的联系人走密封发送，服务端看不到发送者，照常收发；
/// 给自己的其它设备（同步消息、给自己发）也照常。「限制全部发送」另外由证书接口停发送者证书（见 CertificateController）。
///
/// 被拒时 HTTP 回 403，body 是 `{"tellomiRestriction":{"level":…,"until":…,"appeal":…}}`（以后客户端据此显示说明，
/// ADR-0078 §3.4）；gRPC 回 PERMISSION_DENIED。其它情况交给原来的 [SpamChecker]（香港是 noop）。
public class TellomiRestrictionSpamChecker implements SpamChecker {

  public static final String APPEAL_ADDRESS = "abuse@tellomi.app";

  private static final String BLOCKED_COUNTER_NAME = name(TellomiRestrictionSpamChecker.class, "blocked");

  private final TellomiAccountRestrictions restrictions;
  private final SpamChecker delegate;

  public TellomiRestrictionSpamChecker(final TellomiAccountRestrictions restrictions, final SpamChecker delegate) {
    this.restrictions = restrictions;
    this.delegate = delegate;
  }

  @Override
  public SpamCheckResult<Response> checkForIndividualRecipientSpamHttp(final MessageType messageType,
      final ContainerRequestContext requestContext,
      final Optional<org.whispersystems.textsecuregcm.auth.AuthenticatedDevice> maybeSource,
      final Optional<Account> maybeDestination,
      final ServiceIdentifier destinationIdentifier) {

    final Optional<Restriction> restriction =
        blocking(messageType, maybeSource.map(org.whispersystems.textsecuregcm.auth.AuthenticatedDevice::accountIdentifier),
            destinationIdentifier);
    if (restriction.isPresent()) {
      Metrics.counter(BLOCKED_COUNTER_NAME, "transport", "http", "level", restriction.get().level().code()).increment();
      return new SpamCheckResult<>(Optional.of(forbidden(restriction.get())), Optional.empty());
    }
    return delegate.checkForIndividualRecipientSpamHttp(messageType, requestContext, maybeSource, maybeDestination,
        destinationIdentifier);
  }

  @Override
  public SpamCheckResult<Response> checkForMultiRecipientSpamHttp(final MessageType messageType,
      final ContainerRequestContext requestContext) {
    // 多收件人只有密封发送，看不到发送者
    return delegate.checkForMultiRecipientSpamHttp(messageType, requestContext);
  }

  @Override
  public SpamCheckResult<GrpcChallengeResponse> checkForIndividualRecipientSpamGrpc(final MessageType messageType,
      final Optional<org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice> maybeSource,
      final Optional<Account> maybeDestination,
      final ServiceIdentifier destinationIdentifier) {

    final Optional<Restriction> restriction = blocking(messageType,
        maybeSource.map(org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice::accountIdentifier),
        destinationIdentifier);
    if (restriction.isPresent()) {
      Metrics.counter(BLOCKED_COUNTER_NAME, "transport", "grpc", "level", restriction.get().level().code()).increment();
      return new SpamCheckResult<>(Optional.of(GrpcChallengeResponse.withStatusException(
          Status.PERMISSION_DENIED.withDescription("account restricted").asRuntimeException())), Optional.empty());
    }
    return delegate.checkForIndividualRecipientSpamGrpc(messageType, maybeSource, maybeDestination,
        destinationIdentifier);
  }

  @Override
  public SpamCheckResult<GrpcChallengeResponse> checkForMultiRecipientSpamGrpc(final MessageType messageType) {
    return delegate.checkForMultiRecipientSpamGrpc(messageType);
  }

  private Optional<Restriction> blocking(final MessageType messageType, final Optional<UUID> source,
      final ServiceIdentifier destination) {
    if (messageType != MessageType.INDIVIDUAL_IDENTIFIED_SENDER || source.isEmpty()
        || source.get().equals(destination.uuid())) {
      return Optional.empty();
    }
    return restrictions.get(source.get());
  }

  /// 403 + 说明（被处置的档位、到什么时候、申诉邮箱）。
  public static Response forbidden(final Restriction restriction) {
    return Response.status(Response.Status.FORBIDDEN)
        .type(MediaType.APPLICATION_JSON_TYPE)
        .entity(Map.of("tellomiRestriction", Map.of(
            "level", restriction.level().code(),
            "until", restriction.until().getEpochSecond(),
            "appeal", APPEAL_ADDRESS)))
        .build();
  }
}
