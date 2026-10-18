/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import io.dropwizard.auth.Auth;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import java.util.Base64;
import java.util.concurrent.CompletableFuture;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.username.TellomiReleaseProbe;

/// Tellomi（ADR-0066 §6.1；owner 2026-10-18 批准放宽探针账号的限流）：`GET /v1/tellomi/username-probe/{usernameHash}`——
/// 发版闸查「这个用户名有没有人占」的专用接口。
///
/// 公开的查名接口（`GET /v1/accounts/username_hash/{hash}`）不许登录、按 IP 限流，探针在发版那台机器上一晚上就把那个 IP 的
/// 额度用光；它照旧不动。这里只给 `usernamePolicy.releaseProbeAccounts` 里的账号用（别人 403），按账号计
/// `tellomiUsernameProbe` 限流。查的是同一份数据（`AccountsManager.getByUsernameHash`），只回答占没占，不回是谁占的。
/// 回的是 200 加 `{"taken": …}` 而不是 404：服务端还没部署这个接口时探针会拿到 404，借此和「没人占」分开，退回公开接口。
@Path("/v1/tellomi/username-probe")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Tellomi")
public class TellomiUsernameProbeController {

  private final AccountsManager accounts;
  private final RateLimiters rateLimiters;
  private final TellomiReleaseProbe releaseProbe;

  public TellomiUsernameProbeController(final AccountsManager accounts, final RateLimiters rateLimiters,
      final TellomiReleaseProbe releaseProbe) {
    this.accounts = accounts;
    this.rateLimiters = rateLimiters;
    this.releaseProbe = releaseProbe;
  }

  /// @param taken 有账号用着这个用户名 hash
  public record TellomiUsernameProbeResponse(boolean taken) {
  }

  @GET
  @Path("/{usernameHash}")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Release probe: is this username hash taken?",
      description = "Only for the accounts in usernamePolicy.releaseProbeAccounts; everybody else gets 403.")
  @ApiResponse(responseCode = "200", description = "{\"taken\": true | false}")
  @ApiResponse(responseCode = "403", description = "Not a release probe account")
  @ApiResponse(responseCode = "422", description = "Not a base64url 32-byte username hash")
  @ApiResponse(responseCode = "429", description = "Rate limited (tellomiUsernameProbe)")
  public CompletableFuture<TellomiUsernameProbeResponse> lookup(@Auth final AuthenticatedDevice auth,
      @PathParam("usernameHash") final String usernameHash) throws Exception {

    if (!releaseProbe.isProbe(auth.accountIdentifier())) {
      throw new WebApplicationException(Status.FORBIDDEN);
    }
    rateLimiters.forDescriptor(RateLimiters.For.TELLOMI_USERNAME_PROBE).validate(auth.accountIdentifier());

    final byte[] hash;
    try {
      hash = Base64.getUrlDecoder().decode(usernameHash);
    } catch (final IllegalArgumentException e) {
      throw new WebApplicationException(Response.status(422).build());
    }
    if (hash.length != AccountController.USERNAME_HASH_LENGTH) {
      throw new WebApplicationException(Response.status(422).build());
    }

    return accounts.getByUsernameHash(hash).thenApply(account -> new TellomiUsernameProbeResponse(account.isPresent()));
  }
}
