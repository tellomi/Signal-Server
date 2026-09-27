/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.controllers;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Metrics;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Set;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.captcha.Action;
import org.whispersystems.textsecuregcm.captcha.AltchaCaptchaClient;
import org.whispersystems.textsecuregcm.filters.RemoteAddressFilter;

/// Tellomi（ADR-0070 §5.1、§5.3、§5.4）：注册 / 限流验证页（`chat.tellomi.app/captcha-tellomi/…`，同源）用的两个无需登录的接口。
/// App 协议不变：这里只给网页用，令牌照旧经 `tellomicaptcha://` 回到 App，再由 App 交给 `/v1/verification` 或 `/v1/challenge`。
///
/// - `GET /v1/tellomi/captcha/altcha/challenge?action=registration&via=primary`：签发一个 ALTCHA 挑战。**不拒绝**：
///   来源网段越热难度越高（{@link AltchaCaptchaClient#issueChallenge}）。
/// - `POST /v1/tellomi/captcha/event?e=…`：页面上报「出了哪种验证 / 换路及原因 / 耗时 / 重新加载」，只进指标（§5.4 最后一条），
///   参数全部走白名单，不落库。
@Path("/v1/tellomi/captcha")
@io.swagger.v3.oas.annotations.tags.Tag(name = "Tellomi")
public class TellomiCaptchaController {

  private static final String PAGE_EVENT_COUNTER_NAME = name(TellomiCaptchaController.class, "pageEvent");
  private static final String PAGE_SOLVE_MILLIS_NAME = name(TellomiCaptchaController.class, "pageSolveMillis");

  static final Set<String> EVENTS = Set.of("shown", "switch", "solved", "reload", "error");
  static final Set<String> MODES = Set.of("turnstile", "altcha");
  static final Set<String> REASONS = Set.of("load", "error", "timeout", "unsupported", "manual", "expired");

  private final AltchaCaptchaClient altchaCaptchaClient;

  public TellomiCaptchaController(final AltchaCaptchaClient altchaCaptchaClient) {
    this.altchaCaptchaClient = altchaCaptchaClient;
  }

  @GET
  @Path("/altcha/challenge")
  @Produces(MediaType.APPLICATION_JSON)
  @Operation(summary = "Issues an ALTCHA proof-of-work challenge for the captcha web page",
      description = """
          Used only by the captcha web page served from the same origin. The challenge binds the requested action;
          difficulty depends on how many challenges the caller's network segment requested in the last hour. This
          endpoint never refuses: busier sources get harder challenges.
          """)
  @ApiResponse(responseCode = "200", description = "An ALTCHA v2 challenge ({parameters, signature})")
  @ApiResponse(responseCode = "400", description = "Unknown action")
  public Response challenge(@QueryParam("action") @Nullable final String action,
      @QueryParam("via") @Nullable final String via,
      @Context final ContainerRequestContext requestContext) throws Exception {

    final Action parsedAction = action == null ? null : Action.fromString(action);
    if (parsedAction == null) {
      return Response.status(Response.Status.BAD_REQUEST).header("Cache-Control", "no-store").build();
    }

    final String ip = (String) requestContext.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME);
    final AltchaCaptchaClient.IssuedChallenge issued = altchaCaptchaClient.issueChallenge(parsedAction, ip, via);

    return Response.ok(issued.json(), MediaType.APPLICATION_JSON_TYPE)
        .header("Cache-Control", "no-store")
        .build();
  }

  @POST
  @Path("/event")
  @Operation(summary = "Records a captcha page event (metrics only)")
  @ApiResponse(responseCode = "204", description = "Recorded (unknown values are recorded as \"other\")")
  public Response event(@QueryParam("e") @Nullable final String event,
      @QueryParam("mode") @Nullable final String mode,
      @QueryParam("to") @Nullable final String to,
      @QueryParam("reason") @Nullable final String reason,
      @QueryParam("action") @Nullable final String action,
      @QueryParam("ms") @Nullable final Long millis) {

    final String actionTag = action != null && Action.fromString(action) != null ? Action.fromString(action).getActionName() : "other";
    final String modeTag = allow(mode, MODES);

    Metrics.counter(PAGE_EVENT_COUNTER_NAME,
            "event", allow(event, EVENTS),
            "mode", modeTag,
            "to", allow(to, MODES),
            "reason", allow(reason, REASONS),
            "action", actionTag)
        .increment();

    if ("solved".equals(event) && millis != null) {
      DistributionSummary.builder(PAGE_SOLVE_MILLIS_NAME)
          .tags("mode", modeTag, "action", actionTag)
          .publishPercentiles(0.5, 0.9, 0.99)
          .register(Metrics.globalRegistry)
          .record(Math.clamp(millis, 0L, 600_000L));
    }

    return Response.noContent().build();
  }

  private static String allow(@Nullable final String value, final Set<String> allowed) {
    if (value == null || value.isEmpty()) {
      return "none";
    }
    return allowed.contains(value) ? value : "other";
  }
}
