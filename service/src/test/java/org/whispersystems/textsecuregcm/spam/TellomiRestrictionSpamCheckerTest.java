/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.spam;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.identity.AciServiceIdentifier;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions.Level;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions.Restriction;

/// Tellomi（ADR-0078 §3.3）：被处置的账号，非密封发送给别人被拒；密封发送、同步、给自己、没被处置的照常交给原来的检查。
class TellomiRestrictionSpamCheckerTest {

  private static final Instant UNTIL = Instant.parse("2026-10-24T10:00:00Z");

  private final UUID restricted = UUID.randomUUID();
  private final UUID someoneElse = UUID.randomUUID();
  private TellomiAccountRestrictions restrictions;
  private SpamChecker delegate;
  private TellomiRestrictionSpamChecker checker;
  private final ContainerRequestContext context = mock(ContainerRequestContext.class);

  @BeforeEach
  void setUp() {
    restrictions = mock(TellomiAccountRestrictions.class);
    when(restrictions.get(any())).thenReturn(Optional.empty());
    when(restrictions.get(restricted)).thenReturn(Optional.of(new Restriction(Level.STRANGER, UNTIL)));
    delegate = mock(SpamChecker.class);
    when(delegate.checkForIndividualRecipientSpamHttp(any(), any(), any(), any(), any()))
        .thenReturn(new SpamCheckResult<>(Optional.empty(), Optional.empty()));
    when(delegate.checkForIndividualRecipientSpamGrpc(any(), any(), any(), any()))
        .thenReturn(new SpamCheckResult<>(Optional.empty(), Optional.empty()));
    checker = new TellomiRestrictionSpamChecker(restrictions, delegate);
  }

  private SpamCheckResult<Response> http(final MessageType type, final Optional<UUID> source, final UUID destination) {
    return checker.checkForIndividualRecipientSpamHttp(type, context,
        source.map(s -> new AuthenticatedDevice(s, (byte) 1, Instant.EPOCH)), Optional.empty(),
        new AciServiceIdentifier(destination));
  }

  @Test
  @SuppressWarnings("unchecked")
  void identifiedSendFromARestrictedAccountIsForbiddenWithAnExplanation() {
    final SpamCheckResult<Response> result = http(MessageType.INDIVIDUAL_IDENTIFIED_SENDER, Optional.of(restricted), someoneElse);

    final Response response = result.response().orElseThrow();
    assertEquals(403, response.getStatus());
    final Map<String, Object> body = (Map<String, Object>) ((Map<String, Object>) response.getEntity()).get("tellomiRestriction");
    assertEquals("stranger", body.get("level"));
    assertEquals(UNTIL.getEpochSecond(), body.get("until"));
    assertEquals("abuse@tellomi.app", body.get("appeal"));
    verify(delegate, never()).checkForIndividualRecipientSpamHttp(any(), any(), any(), any(), any());
  }

  @Test
  void everythingElseGoesToTheUpstreamChecker() {
    // 密封发送（看不到发送者）、同步消息、给自己发、没被处置的人
    assertTrue(http(MessageType.INDIVIDUAL_SEALED_SENDER, Optional.empty(), someoneElse).response().isEmpty());
    assertTrue(http(MessageType.SYNC, Optional.of(restricted), restricted).response().isEmpty());
    assertTrue(http(MessageType.INDIVIDUAL_IDENTIFIED_SENDER, Optional.of(restricted), restricted).response().isEmpty());
    assertTrue(http(MessageType.INDIVIDUAL_IDENTIFIED_SENDER, Optional.of(someoneElse), restricted).response().isEmpty());
  }

  @Test
  void grpcIsDeniedTheSameWay() {
    final SpamCheckResult<GrpcChallengeResponse> result = checker.checkForIndividualRecipientSpamGrpc(
        MessageType.INDIVIDUAL_IDENTIFIED_SENDER,
        Optional.of(new org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice(restricted, (byte) 1)),
        Optional.empty(), new AciServiceIdentifier(someoneElse));

    final StatusRuntimeException e = assertThrows(StatusRuntimeException.class,
        () -> result.response().orElseThrow().getResponseOrThrowStatus());
    assertEquals(Status.Code.PERMISSION_DENIED, e.getStatus().getCode());

    assertTrue(checker.checkForIndividualRecipientSpamGrpc(MessageType.INDIVIDUAL_IDENTIFIED_SENDER,
        Optional.of(new org.whispersystems.textsecuregcm.auth.grpc.AuthenticatedDevice(someoneElse, (byte) 1)),
        Optional.empty(), new AciServiceIdentifier(restricted)).response().isEmpty());
  }
}
