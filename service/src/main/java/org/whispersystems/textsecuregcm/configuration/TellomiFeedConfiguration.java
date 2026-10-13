/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import java.util.List;
import java.util.Locale;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;

/// Tellomi（ADR-0071 §5.3）：给动态的内容引擎签短期凭证、好友声明和受众名单。
///
/// @param signingKey     HS256 签名密钥，和内容引擎 `ENGINE_FEED_AUTH_KEYS` 的第一把（最新那把）是同一把，至少 32 字节
/// @param pseudonymKey   派生假名的密钥：`sub = HMAC-SHA256(pseudonymKey, ACI 字符串)` 取前 16 字节。**一旦上线不能换**，
///                       换了所有人在内容引擎里的身份（主页、关注、好友）都会断；内容引擎不需要它，至少 32 字节
/// @param cnHostSuffixes 经这些主机进来的请求算大陆区（§5.3「取严」的入口一项）；缺省 `tellomi.cn`
public record TellomiFeedConfiguration(@NotNull SecretBytes signingKey,
                                       @NotNull SecretBytes pseudonymKey,
                                       @Nullable List<String> cnHostSuffixes) {

  public static final List<String> DEFAULT_CN_HOST_SUFFIXES = List.of("tellomi.cn");

  public TellomiFeedConfiguration {
    if (signingKey != null && signingKey.value().length < 32) {
      throw new IllegalArgumentException("tellomiFeed.signingKey must be at least 32 bytes");
    }
    if (pseudonymKey != null && pseudonymKey.value().length < 32) {
      throw new IllegalArgumentException("tellomiFeed.pseudonymKey must be at least 32 bytes");
    }
    if (signingKey != null && pseudonymKey != null
        && java.security.MessageDigest.isEqual(signingKey.value(), pseudonymKey.value())) {
      throw new IllegalArgumentException("tellomiFeed.signingKey and pseudonymKey must differ");
    }
    cnHostSuffixes = cnHostSuffixes == null || cnHostSuffixes.isEmpty()
        ? DEFAULT_CN_HOST_SUFFIXES
        : cnHostSuffixes.stream().map(s -> s.toLowerCase(Locale.ROOT)).toList();
  }
}
