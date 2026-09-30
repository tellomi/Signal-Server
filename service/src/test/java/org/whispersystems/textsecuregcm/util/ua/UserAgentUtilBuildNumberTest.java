/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util.ua;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.vdurmont.semver4j.Semver;
import java.util.OptionalLong;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/// tellomi/tellomi#1399：从 User-Agent 的附加段里取 `Build/<十进制整数>`。没有、写得不对、太大，都当「没有」，不抛异常。
class UserAgentUtilBuildNumberTest {

  private static OptionalLong buildNumber(final String userAgentString) throws UnrecognizedUserAgentException {
    return UserAgentUtil.parseBuildNumber(UserAgentUtil.parseUserAgentString(userAgentString));
  }

  @ParameterizedTest
  @MethodSource
  void parseBuildNumber(final String userAgentString, final OptionalLong expected) throws Exception {
    assertThat(buildNumber(userAgentString)).isEqualTo(expected);
  }

  private static Stream<Arguments> parseBuildNumber() {
    return Stream.of(
        // 三端现在真实发的形状（取自各客户端 fork 的源码与测试）
        Arguments.argumentSet("Android: versionCode", "Signal-Android/0.1.2 Android/34 Build/175101",
            OptionalLong.of(175101)),
        Arguments.argumentSet("iOS: 构建号", "Signal-iOS/0.1.2 iOS/26.0 Build/37", OptionalLong.of(37)),
        Arguments.argumentSet("iOS: 第一个 TestFlight 包的构建号是 0（0 是合法的构建号，不是「没有」）",
            "Signal-iOS/0.1.0 iOS/26.0 Build/0", OptionalLong.of(0)),
        Arguments.argumentSet("Desktop: 没有 Build/ 段，只有系统信息", "Signal-Desktop/0.1.10 macOS 25.0.0",
            OptionalLong.empty()),
        Arguments.argumentSet("Desktop: 连系统信息都没有", "Signal-Desktop/0.1.10", OptionalLong.empty()),

        // 老包 / 没有构建号
        Arguments.argumentSet("Android 老包：没有 Build/ 段", "Signal-Android/0.1.2 Android/34", OptionalLong.empty()),
        Arguments.argumentSet("iOS 老包：没有 Build/ 段", "Signal-iOS/0.1.2 iOS/26.0", OptionalLong.empty()),
        Arguments.argumentSet("没有任何附加段", "Signal-Android/0.1.2", OptionalLong.empty()),
        Arguments.argumentSet("上游自己的老格式", "Signal-iOS/3.9.0 (iPhone; iOS 12.2; Scale/3.00)", OptionalLong.empty()),

        // 位置无关、多余空格
        Arguments.argumentSet("Build/ 不在最后", "Signal-Android/0.1.2 Build/175101 Android/34", OptionalLong.of(175101)),
        Arguments.argumentSet("Build/ 是唯一的附加段", "Signal-Android/0.1.2 Build/5", OptionalLong.of(5)),
        Arguments.argumentSet("多个空格", "Signal-Android/0.1.2  Android/34   Build/175101", OptionalLong.of(175101)),
        Arguments.argumentSet("前导 0 按十进制", "Signal-Android/0.1.2 Android/34 Build/007", OptionalLong.of(7)),

        // 写得不对 → 当没有（不抛异常）
        Arguments.argumentSet("Build/abc", "Signal-Android/0.1.2 Android/34 Build/abc", OptionalLong.empty()),
        Arguments.argumentSet("数字后面跟字母", "Signal-Android/0.1.2 Android/34 Build/12abc", OptionalLong.empty()),
        Arguments.argumentSet("空值", "Signal-Android/0.1.2 Android/34 Build/", OptionalLong.empty()),
        Arguments.argumentSet("负数", "Signal-Android/0.1.2 Android/34 Build/-5", OptionalLong.empty()),
        Arguments.argumentSet("带加号", "Signal-Android/0.1.2 Android/34 Build/+5", OptionalLong.empty()),
        Arguments.argumentSet("带小数点（iOS 版本多于四段时构建号会是 37.5 这种）",
            "Signal-iOS/0.1.2 iOS/26.0 Build/37.5", OptionalLong.empty()),
        Arguments.argumentSet("科学计数法", "Signal-Android/0.1.2 Android/34 Build/1e3", OptionalLong.empty()),
        Arguments.argumentSet("全角数字", "Signal-Android/0.1.2 Android/34 Build/１２３", OptionalLong.empty()),
        Arguments.argumentSet("十六进制", "Signal-Android/0.1.2 Android/34 Build/0x10", OptionalLong.empty()),
        Arguments.argumentSet("大小写必须是 Build/", "Signal-Android/0.1.2 Android/34 build/5", OptionalLong.empty()),
        Arguments.argumentSet("必须是独立的一段，不能粘在别的字符后面", "Signal-Android/0.1.2 Android/34 xBuild/5",
            OptionalLong.empty()),
        Arguments.argumentSet("不能粘在前一段后面", "Signal-Android/0.1.2 Android/34Build/5", OptionalLong.empty()),
        Arguments.argumentSet("不是空格分隔（制表符）", "Signal-Android/0.1.2 Android/34\tBuild/5", OptionalLong.empty()),

        // long 的边界：Long.MAX_VALUE 合法，再大一个就当「没有」
        Arguments.argumentSet("Long.MAX_VALUE", "Signal-Android/0.1.2 Build/9223372036854775807",
            OptionalLong.of(Long.MAX_VALUE)),
        Arguments.argumentSet("Long.MAX_VALUE + 1", "Signal-Android/0.1.2 Build/9223372036854775808",
            OptionalLong.empty()),
        Arguments.argumentSet("远超 long", "Signal-Android/0.1.2 Android/34 Build/99999999999999999999",
            OptionalLong.empty()),

        // 出现多次：第一个 Build/ 段说了算，它写得不对就是「没有」（不去猜后面那个）
        Arguments.argumentSet("两个 Build/：取第一个", "Signal-Android/0.1.2 Build/1 Build/2", OptionalLong.of(1)),
        Arguments.argumentSet("两个 Build/：第一个写坏了就是没有", "Signal-Android/0.1.2 Build/abc Build/2",
            OptionalLong.empty()));
  }

  @Test
  void noUserAgentMeansNoBuildNumber() {
    assertThat(UserAgentUtil.parseBuildNumber(null)).isEmpty();
  }

  @Test
  void noAdditionalSpecifiersMeansNoBuildNumber() {
    assertThat(UserAgentUtil.parseBuildNumber(new UserAgent(ClientPlatform.ANDROID, new Semver("0.1.2"), null)))
        .isEmpty();
    assertThat(UserAgentUtil.parseBuildNumber(new UserAgent(ClientPlatform.ANDROID, new Semver("0.1.2"), "")))
        .isEmpty();
  }

  @Test
  void theUserAgentRecordIsUntouched() throws Exception {
    // 构建号从 additionalSpecifiers 里取，不改 UserAgent 的形状：附加段原样保留
    final UserAgent userAgent = UserAgentUtil.parseUserAgentString("Signal-Android/0.1.2 Android/34 Build/175101");

    assertThat(userAgent).isEqualTo(
        new UserAgent(ClientPlatform.ANDROID, new Semver("0.1.2"), "Android/34 Build/175101"));
    assertThat(userAgent.version()).isEqualTo(new Semver("0.1.2"));
  }

  /// 进来的 User-Agent 是客户端随便写的：什么都不能让解析抛出来（抛出来就是每个请求 500）
  @ParameterizedTest
  @MethodSource
  void neverThrows(final String additionalSpecifiers) {
    assertThatCode(() -> UserAgentUtil.parseBuildNumber(
        new UserAgent(ClientPlatform.IOS, new Semver("1.0.0"), additionalSpecifiers))).doesNotThrowAnyException();
  }

  private static Stream<String> neverThrows() {
    return Stream.of("Build/", "Build/ ", " Build/1", "Build/" + "9".repeat(10_000), "Build/\u0000", "Build/1\u0000",
        "😀 Build/😀", "Build/Build/1", "  ", "Build", "Build/-", "Build/0000000000000000000000000001");
  }
}
