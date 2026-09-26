/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.google.common.net.HttpHeaders;
import io.micrometer.core.instrument.Metrics;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.util.Optional;
import javax.annotation.Nullable;
import org.apache.http.HttpStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.auth.InvalidRegistrationSessionException;
import org.whispersystems.textsecuregcm.auth.PhoneVerificationTokenManager;
import org.whispersystems.textsecuregcm.auth.RecoveryPasswordVerificationFailedException;
import org.whispersystems.textsecuregcm.auth.StoredRegistrationLock;
import org.whispersystems.textsecuregcm.auth.UnverifiedRegistrationSessionException;
import org.whispersystems.textsecuregcm.filters.RemoteAddressFilter;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.util.E164;
import org.whispersystems.textsecuregcm.util.Util;

/// Tellomi（Google Play 删号）：网页自助删号。Google Play 要求能在应用外发起删号，owner 2026-09-26 选了网页自助：
/// 页面（https://chat.tellomi.app/delete-account/）先走 /v1/verification 短信验证拿到已验证的会话，再调这里。
/// 只凭短信不能删开着注册锁（或两步验证）的账号，否则换卡（SIM swap）的人就能把别人的号删掉；这类账号回 423，请用户在 App 里删。
@Path("/v1/tellomi/account-deletion")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Tellomi")
public class TellomiAccountDeletionController {

  private static final Logger logger = LoggerFactory.getLogger(TellomiAccountDeletionController.class);

  private static final String DELETION_COUNTER_NAME = name(TellomiAccountDeletionController.class, "webDeletion");
  private static final String OUTCOME_TAG_NAME = "outcome";
  private static final String COUNTRY_CODE_TAG_NAME = "countryCode";

  private static final String DELETED = "deleted";
  private static final String SESSION_NOT_VERIFIED = "session_not_verified";
  private static final String INVALID_SESSION = "invalid_session";
  private static final String UNAVAILABLE = "unavailable";
  private static final String RATE_LIMITED = "rate_limited";
  private static final String NOT_REGISTERED = "not_registered";
  private static final String REGISTRATION_LOCK = "registration_lock";
  private static final String MFA = "mfa";

  private static final int LOCKED = 423;

  private final AccountsManager accountsManager;
  private final PhoneVerificationTokenManager phoneVerificationTokenManager;
  private final RateLimiters rateLimiters;

  public TellomiAccountDeletionController(final AccountsManager accountsManager,
      final PhoneVerificationTokenManager phoneVerificationTokenManager,
      final RateLimiters rateLimiters) {

    this.accountsManager = accountsManager;
    this.phoneVerificationTokenManager = phoneVerificationTokenManager;
    this.rateLimiters = rateLimiters;
  }

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Deletes an account after SMS verification (web self-service)",
      description = """
          Deletes the account registered to `number`, given the ID of a verification session for that number that has
          been verified by SMS (see /v1/verification). Accounts with a registration lock that is still in force, or
          with a second factor, are never deleted this way; delete those from the app.
          """)
  @ApiResponse(responseCode = "204", description = "The account was deleted")
  @ApiResponse(responseCode = "400", description = "The number does not match the session, or the session ID was rejected",
      content = @Content(schema = @Schema(implementation = FailureResponse.class)))
  @ApiResponse(responseCode = "401", description = "The session is unknown, expired, or not verified",
      content = @Content(schema = @Schema(implementation = FailureResponse.class)))
  @ApiResponse(responseCode = "404", description = "No account is registered to the number",
      content = @Content(schema = @Schema(implementation = FailureResponse.class)))
  @ApiResponse(responseCode = "422", description = "The request did not pass validation, or the session ID is malformed")
  @ApiResponse(responseCode = "423", description = "The account has a registration lock in force or a second factor",
      content = @Content(schema = @Schema(implementation = FailureResponse.class)))
  @ApiResponse(responseCode = "429", description = "Too many attempts", headers = @Header(
      name = "Retry-After",
      description = "If present, a positive integer indicating the number of seconds before a subsequent attempt could succeed"))
  @ApiResponse(responseCode = "503", description = "The registration service is unavailable",
      content = @Content(schema = @Schema(implementation = FailureResponse.class)))
  public Response deleteAccount(@NotNull @Valid final AccountDeletionRequest request,
      @Context final ContainerRequestContext requestContext)
      throws RateLimitExceededException, InterruptedException {

    final String number = request.number();
    final byte[] sessionId = request.decodeSessionId();

    try {
      // 与注册相同的校验（RegistrationController）：只认会话，不认恢复密码
      phoneVerificationTokenManager.verify(number,
          requestContext.getHeaderString(HttpHeaders.USER_AGENT),
          requestContext.getHeaderString(HttpHeaders.ACCEPT_LANGUAGE),
          (String) requestContext.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME),
          sessionId,
          null);
    } catch (final UnverifiedRegistrationSessionException e) {
      return failure(number, Response.Status.UNAUTHORIZED.getStatusCode(), SESSION_NOT_VERIFIED, null);
    } catch (final InvalidRegistrationSessionException e) {
      return failure(number, Response.Status.BAD_REQUEST.getStatusCode(), INVALID_SESSION, null);
    } catch (final IOException e) {
      return failure(number, Response.Status.SERVICE_UNAVAILABLE.getStatusCode(), UNAVAILABLE, null);
    } catch (final RecoveryPasswordVerificationFailedException e) {
      // 不会发生：上面没有传恢复密码
      throw new AssertionError(e);
    }

    // 限流放在验证之后，和 RegistrationController 一样：放在前面的话，没验证过的人也能耗光别人号码的注册额度
    try {
      rateLimiters.getRegistrationLimiter().validate(number);
    } catch (final RateLimitExceededException e) {
      countOutcome(number, RATE_LIMITED);
      throw e;
    }

    // 同一号码的等价写法（如贝宁新旧号段）最多对应一个账号，查法与 RegistrationController 相同
    final Optional<Account> maybeAccount = Util.getAlternateForms(number).stream()
        .map(accountsManager::getByE164)
        .flatMap(Optional::stream)
        .findFirst();

    if (maybeAccount.isEmpty()) {
      return failure(number, Response.Status.NOT_FOUND.getStatusCode(), NOT_REGISTERED, null);
    }

    final Account account = maybeAccount.get();

    // 注册锁仍有效（REQUIRED）就不删；已过期（EXPIRED）或没有（ABSENT）才放行，判定与 RegistrationLockVerificationManager 相同。
    // 不调用 verifyRegistrationLock：PIN 不对时它会冻结账号凭据、断开所有设备并推送，删号页不该有这些副作用。
    final StoredRegistrationLock registrationLock = account.getRegistrationLock();
    if (registrationLock.getStatus() == StoredRegistrationLock.Status.REQUIRED) {
      return failure(number, LOCKED, REGISTRATION_LOCK, registrationLock.getTimeRemaining().toMillis());
    }

    // 两步验证同理：上游重新注册要求第二因素（RegistrationController.checkMfa），只凭短信也不能删
    if (!account.getMfaKeys().isEmpty()) {
      return failure(number, LOCKED, MFA, null);
    }

    // 与 DELETE /v1/accounts/me 相同的删除原因
    accountsManager.delete(account.getAccountIdentifier(), AccountsManager.DeletionReason.USER_REQUEST);

    logger.info("Tellomi: account {} ({}) deleted by web self-service after SMS verification",
        account.getAccountIdentifier(), redactPhoneNumber(number));
    countOutcome(number, DELETED);

    return Response.noContent().build();
  }

  private static Response failure(final String number, final int status, final String reason,
      @Nullable final Long timeRemaining) {

    countOutcome(number, reason);

    return Response.status(status)
        .type(MediaType.APPLICATION_JSON_TYPE)
        .entity(new FailureResponse(reason, timeRemaining))
        .build();
  }

  private static void countOutcome(final String number, final String outcome) {
    Metrics.counter(DELETION_COUNTER_NAME,
            OUTCOME_TAG_NAME, outcome,
            COUNTRY_CODE_TAG_NAME, Util.getCountryCode(number))
        .increment();
  }

  /// 日志里不写完整号码，格式与上游 Accounts.redactPhoneNumber 相同（+国家码???末两位）
  private static String redactPhoneNumber(final String number) {
    return "+" + Util.getCountryCode(number) + "???" + number.substring(number.length() - 2);
  }

  public record AccountDeletionRequest(
      @Schema(requiredMode = Schema.RequiredMode.REQUIRED,
          description = "The e164-formatted phone number whose account is to be deleted")
      @E164
      @NotBlank
      String number,

      @Schema(requiredMode = Schema.RequiredMode.REQUIRED, description = """
          The ID of a verified verification session for `number`, exactly as it appears in the verification session
          metadata (URL-safe base64), i.e. the same value the registration API accepts as `sessionId`
          """)
      @NotBlank
      String sessionId) {

    /// 与 PhoneVerificationRequest.decodeSessionId() 相同：URL-safe base64，解不开回 422
    byte[] decodeSessionId() {
      try {
        return VerificationController.decodeSessionId(sessionId);
      } catch (final IllegalArgumentException e) {
        throw new ClientErrorException("Malformed session ID", HttpStatus.SC_UNPROCESSABLE_ENTITY);
      }
    }
  }

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record FailureResponse(
      @Schema(description = """
          Why the account was not deleted: session_not_verified, invalid_session, unavailable, not_registered,
          registration_lock or mfa
          """)
      String reason,

      @Schema(requiredMode = Schema.RequiredMode.NOT_REQUIRED, description = """
          For registration_lock only: milliseconds until the lock expires if the account stays idle (the same value as
          timeRemaining in the registration API's 423 response)
          """)
      @Nullable
      Long timeRemaining) {
  }
}
