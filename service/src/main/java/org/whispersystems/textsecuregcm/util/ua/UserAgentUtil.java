/*
 * Copyright 2013-2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util.ua;

import com.vdurmont.semver4j.Semver;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import javax.annotation.Nullable;

public class UserAgentUtil {

  private static final Pattern STANDARD_UA_PATTERN = Pattern.compile("^Signal-(Android|Desktop|iOS)/([^ ]+)( (.+))?$", Pattern.CASE_INSENSITIVE);

  private static final String BUILD_NUMBER_PREFIX = "Build/";

  public static UserAgent parseUserAgentString(final String userAgentString) throws UnrecognizedUserAgentException {
    if (StringUtils.isBlank(userAgentString)) {
      throw new UnrecognizedUserAgentException("User-Agent string is blank");
    }

    try {
      final Matcher matcher = STANDARD_UA_PATTERN.matcher(userAgentString);

      if (matcher.matches()) {
        return new UserAgent(ClientPlatform.valueOf(matcher.group(1).toUpperCase()), new Semver(matcher.group(2)), StringUtils.stripToNull(matcher.group(4)));
      }
    } catch (final Exception e) {
      throw new UnrecognizedUserAgentException(e);
    }

    throw new UnrecognizedUserAgentException();
  }

  public static @Nullable UserAgent maybeParseUserAgentString(final String userAgentString) {
    try {
      return parseUserAgentString(userAgentString);
    } catch (UnrecognizedUserAgentException e) {
      return null;
    }
  }

  /// Tellomi（tellomi/tellomi#1399，需求 app-update-and-version-policy 3.3）：取 User-Agent 里的构建号。
  ///
  /// Tellomi 的 Android / iOS 在 User-Agent 末尾带一个 `Build/<十进制整数>` 段（Android 是 versionCode，iOS 是 CFBundleVersion），
  /// 例如 `Signal-Android/0.1.2 Android/34 Build/175101`、`Signal-iOS/0.1.2 iOS/26.0 Build/37`；Desktop 没有这一段。
  /// 版本号仍然是三段 semver，`UserAgent` 的形状不变，构建号从 `additionalSpecifiers` 里读：
  /// 同一个 versionName 的热修包版本号分不出来，构建号分得出来。
  ///
  /// 要求这一段是用空格隔开的独立一段、写成 `Build/` + 只含 ASCII 数字的十进制整数（`0` 合法，iOS 第一个 TestFlight 包就是 0）。
  /// 没有这一段、写得不对（`Build/abc`、`Build/-5`、`Build/37.5`、全角数字）、超过 `long`，一律当「没有」，不抛异常：
  /// 这个字符串是客户端随便写的，解析它不能让任何请求出错。出现多次时第一个 `Build/` 段说了算，它写坏了就是「没有」。
  public static OptionalLong parseBuildNumber(@Nullable final UserAgent userAgent) {
    if (userAgent == null || userAgent.additionalSpecifiers() == null) {
      return OptionalLong.empty();
    }

    for (final String specifier : userAgent.additionalSpecifiers().split(" ")) {
      if (specifier.startsWith(BUILD_NUMBER_PREFIX)) {
        return parseDecimal(specifier.substring(BUILD_NUMBER_PREFIX.length()));
      }
    }

    return OptionalLong.empty();
  }

  private static OptionalLong parseDecimal(final String digits) {
    if (digits.isEmpty()) {
      return OptionalLong.empty();
    }

    for (int i = 0; i < digits.length(); i++) {
      final char c = digits.charAt(i);

      // 不用 Long.parseLong 直接判断：它接受 `+5`、`-5` 和全角数字
      if (c < '0' || c > '9') {
        return OptionalLong.empty();
      }
    }

    try {
      return OptionalLong.of(Long.parseLong(digits));
    } catch (final NumberFormatException e) {
      // 超过 Long.MAX_VALUE
      return OptionalLong.empty();
    }
  }
}
