/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.HttpHeaders;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.filters.RemoteAddressFilter;

/// 一次评估的输入：ADR-0070 §6.2 表里「服务端现成可得、不用改客户端」的信号。
///
/// 全是普通字符串 / 布尔值，构造时不做任何解析，所以在请求线程上构造它不会抛异常；解析（IP、号码、User-Agent）都在后台线程做。
/// **这个对象和它里面的值绝不写进日志**（号码和 IP 不落明文，§6.2 隐私）。
///
/// @param sourceAddress    请求来源地址（`RemoteAddressFilter` 覆盖过的真实来源）；发码后 / 验码这两步不需要，可以是 null
/// @param e164             号码（E.164）
/// @param userAgent        `User-Agent` 请求头；可能没有
/// @param sessionId        验证会话号（base64url）。只用来找「这个会话当初本来会不会放行」，哈希后使用
/// @param pushTokenPresent 建会话请求里是否带了推送 token（带了的多半会走推送挑战，指标里分开看）
public record RiskSignals(@Nullable String sourceAddress,
                          String e164,
                          @Nullable String userAgent,
                          String sessionId,
                          boolean pushTokenPresent) {

  /// 从请求里取来源地址和 User-Agent。**不抛异常**：取不到就当没有（判定里对应的信号会是「判不出」，不影响请求）
  public static RiskSignals fromRequest(final ContainerRequestContext requestContext, final String e164,
      final String sessionId, final boolean pushTokenPresent) {

    String sourceAddress = null;
    String userAgent = null;

    try {
      if (requestContext.getProperty(RemoteAddressFilter.REMOTE_ADDRESS_ATTRIBUTE_NAME) instanceof String address) {
        sourceAddress = address;
      }
      userAgent = requestContext.getHeaderString(HttpHeaders.USER_AGENT);
    } catch (final RuntimeException ignored) {
    }

    return new RiskSignals(sourceAddress, e164, userAgent, sessionId, pushTokenPresent);
  }

  /// 发码之后 / 验码之后的事件只需要号码和会话号
  public static RiskSignals forSession(final String e164, final String sessionId) {
    return new RiskSignals(null, e164, null, sessionId, false);
  }
}
