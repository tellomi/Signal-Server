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
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.auth.AuthenticatedDevice;
import org.whispersystems.textsecuregcm.spam.TellomiRestrictionSpamChecker;
import org.whispersystems.textsecuregcm.storage.TellomiAccountRestrictions;

/// Tellomi（ADR-0078 §3.4 第三刀）：`GET /v1/tellomi/restriction`——自己的账号现在有没有生效的人工处置。
///
/// 客户端在发消息 / 取发送证书被拒（403）和回到前台时问一次，有就在聊天列表顶上显示说明：iOS 的发送走 libsignal，
/// 403 的 body 在那里读不到，所以单独给一个接口。只返回自己的处置；body 和 403 里的一样（level / until / appeal / case），
/// 不含举报人、举报次数。没有处置、或者服务端没开处置名单，都是 204。被暂停的账号鉴权就过不去，用不到这里。
@Path("/v1/tellomi/restriction")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Tellomi")
public class TellomiRestrictionController {

  @Nullable
  private final TellomiAccountRestrictions restrictions;

  public TellomiRestrictionController(@Nullable final TellomiAccountRestrictions restrictions) {
    this.restrictions = restrictions;
  }

  @GET
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Returns the caller's active moderation restriction, if any",
      description = "Same body as the 403 a restricted send gets: {\"tellomiRestriction\":{level, until, appeal, case}}.")
  @ApiResponse(responseCode = "200", description = "The account has an active restriction")
  @ApiResponse(responseCode = "204", description = "No active restriction")
  public Response get(@Auth final AuthenticatedDevice auth) {
    if (restrictions == null) {
      return Response.noContent().header("Cache-Control", "no-store").build();
    }
    return restrictions.get(auth.accountIdentifier())
        .map(restriction -> Response.fromResponse(TellomiRestrictionSpamChecker.withExplanation(200, restriction))
            .header("Cache-Control", "no-store")
            .build())
        .orElseGet(() -> Response.noContent().header("Cache-Control", "no-store").build());
  }
}
