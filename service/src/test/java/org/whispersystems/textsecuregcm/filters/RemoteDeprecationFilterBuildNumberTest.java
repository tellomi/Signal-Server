/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.filters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.net.HttpHeaders;
import com.google.common.net.InetAddresses;
import com.google.protobuf.ByteString;
import com.google.rpc.ErrorInfo;
import com.google.rpc.Status;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.protobuf.StatusProto;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.signal.chat.rpc.EchoRequest;
import org.signal.chat.rpc.EchoServiceGrpc;
import org.whispersystems.textsecuregcm.auth.AccountAuthenticator;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.grpc.EchoServiceImpl;
import org.whispersystems.textsecuregcm.grpc.GrpcExceptions;
import org.whispersystems.textsecuregcm.grpc.MockRequestAttributesInterceptor;
import org.whispersystems.textsecuregcm.grpc.RequestAttributes;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.tests.util.FakeDynamicConfigurationManager;
import org.whispersystems.textsecuregcm.util.ua.UserAgentUtil;

/// tellomi/tellomi#1399：按构建号拒绝旧版本（`remoteDeprecation.minimumBuilds` / `blockedBuilds`）。
///
/// 配置一律从 YAML 经真实的动态配置解析得到；HTTP（499）与 gRPC（`UPGRADE_REQUIRED`）两条路径共用 `shouldBlock`，都测。
/// 「没配构建号规则时行为不变」由 `RemoteDeprecationFilterCompatibilityTest` 守着。
class RemoteDeprecationFilterBuildNumberTest {

  // 三端现在真实发的 User-Agent 形状（取自各客户端 fork 的源码与测试）
  private static final String ANDROID_175101 = "Signal-Android/0.1.2 Android/34 Build/175101";
  // 同一个 versionName（0.1.2）的热修包：构建号不同，版本号分不出来
  private static final String ANDROID_175102 = "Signal-Android/0.1.2 Android/34 Build/175102";
  private static final String ANDROID_175103 = "Signal-Android/0.1.2 Android/34 Build/175103";
  private static final String ANDROID_NO_BUILD = "Signal-Android/0.1.2 Android/34";
  private static final String ANDROID_BAD_BUILD = "Signal-Android/0.1.2 Android/34 Build/abc";
  private static final String IOS_37 = "Signal-iOS/0.1.2 iOS/26.0 Build/37";
  private static final String IOS_36 = "Signal-iOS/0.1.2 iOS/26.0 Build/36";
  private static final String IOS_0 = "Signal-iOS/0.1.0 iOS/26.0 Build/0";
  private static final String DESKTOP = "Signal-Desktop/0.1.10 macOS 25.0.0";
  private static final String UNRECOGNIZED = "curl/8.0.1";

  private static final String REQUIRED_CONFIG = """
      captcha:
        scoreFloor: 1.0
      """;

  // ---- 配置 ----
  private static final String NONE = "";

  private static final String VERSIONS_ONLY = """
      remoteDeprecation:
        minimumVersions:
          ANDROID: 0.1.3
          DESKTOP: 0.1.11
      """;

  private static final String MINIMUM_BUILD = """
      remoteDeprecation:
        minimumBuilds:
          ANDROID: 175102
      """;

  private static final String BLOCKED_BUILD = """
      remoteDeprecation:
        blockedBuilds:
          ANDROID: [175101]
      """;

  /// 版本规则（0.1.2 < 0.1.3）和构建号规则（175101 < 175102）对同一个包都命中
  private static final String BOTH_MINIMUMS = """
      remoteDeprecation:
        minimumVersions:
          ANDROID: 0.1.3
        minimumBuilds:
          ANDROID: 175102
      """;

  /// 版本号过得去（0.1.2 ≥ 0.1.0），只有构建号低
  private static final String VERSION_PASSES_BUILD_FAILS = """
      remoteDeprecation:
        minimumVersions:
          ANDROID: 0.1.0
        minimumBuilds:
          ANDROID: 175102
      """;

  private static final String MINIMUM_ON_ALL_PLATFORMS = """
      remoteDeprecation:
        minimumBuilds:
          ANDROID: 175102
          IOS: 37
          DESKTOP: 5
      """;

  private static final String MINIMUM_AND_BLOCKED = """
      remoteDeprecation:
        minimumBuilds:
          ANDROID: 175000
        blockedBuilds:
          ANDROID: [175101]
      """;

  private static RemoteDeprecationFilter filter(final String remoteDeprecationYaml) {
    final DynamicConfiguration configuration = DynamicConfigurationManager
        .parseConfiguration(REQUIRED_CONFIG + remoteDeprecationYaml, DynamicConfiguration.class)
        .orElseThrow(() -> new AssertionError("configuration should parse: " + remoteDeprecationYaml));

    return new RemoteDeprecationFilter(mock(AccountsManager.class), mock(AccountAuthenticator.class),
        new FakeDynamicConfigurationManager<>(configuration));
  }

  private record Outcome(boolean block, List<String> deprecated, List<String> pending) {
  }

  private static Outcome evaluate(final String remoteDeprecationYaml, final String userAgentString) {
    final RemoteDeprecationFilter filter = filter(remoteDeprecationYaml);
    final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    final boolean block;

    Metrics.addRegistry(registry);
    try {
      block = filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(userAgentString), null);
    } finally {
      Metrics.removeRegistry(registry);
    }

    return new Outcome(block,
        counters(registry, "chat.RemoteDeprecationFilter.deprecated"),
        counters(registry, "chat.RemoteDeprecationFilter.pendingDeprecation"));
  }

  private static List<String> counters(final SimpleMeterRegistry registry, final String meterName) {
    return registry.find(meterName).meters().stream()
        .filter(meter -> meter instanceof Counter counter && counter.count() > 0)
        .map(meter -> meter.getId().getTag("platform") + ":" + meter.getId().getTag("reason") + "="
            + (long) ((Counter) meter).count())
        .sorted()
        .toList();
  }

  // ---- shouldBlock 真值表（配置 × User-Agent）----

  @ParameterizedTest
  @MethodSource
  void shouldBlock(final String remoteDeprecationYaml, final String userAgent, final boolean expectBlock,
      final List<String> expectDeprecated) {

    final Outcome outcome = evaluate(remoteDeprecationYaml, userAgent);

    assertThat(outcome.block()).as("block").isEqualTo(expectBlock);
    assertThat(outcome.deprecated()).as("deprecated counters").containsExactlyElementsOf(expectDeprecated);
    assertThat(outcome.pending()).as("pendingDeprecation counters").isEmpty();
  }

  private static Stream<Arguments> shouldBlock() {
    final List<String> none = List.of();

    return Stream.of(
        // 没配置：什么都不拦（和改动前一样；逐项对照见 RemoteDeprecationFilterCompatibilityTest）
        Arguments.argumentSet("无配置 / Android 带构建号", NONE, ANDROID_175101, false, none),
        Arguments.argumentSet("无配置 / iOS 带构建号", NONE, IOS_0, false, none),
        Arguments.argumentSet("无配置 / Desktop", NONE, DESKTOP, false, none),
        Arguments.argumentSet("无配置 / 坏构建号", NONE, ANDROID_BAD_BUILD, false, none),
        Arguments.argumentSet("无配置 / 认不出的 UA", NONE, UNRECOGNIZED, false, none),

        // 只有旧字段：带 Build/ 的 UA 仍然只按版本判，指标标签值还是原来的 expired
        Arguments.argumentSet("只有 minimumVersions / Android 带构建号", VERSIONS_ONLY, ANDROID_175101, true,
            List.of("android:expired=1")),
        Arguments.argumentSet("只有 minimumVersions / Android 老包", VERSIONS_ONLY, ANDROID_NO_BUILD, true,
            List.of("android:expired=1")),
        Arguments.argumentSet("只有 minimumVersions / Desktop", VERSIONS_ONLY, DESKTOP, true,
            List.of("desktop:expired=1")),
        Arguments.argumentSet("只有 minimumVersions / iOS 没有规则", VERSIONS_ONLY, IOS_37, false, none),

        // minimumBuilds：构建号小于它的拒绝，等于不拒
        Arguments.argumentSet("minimumBuilds / 低于", MINIMUM_BUILD, ANDROID_175101, true,
            List.of("android:expired_build=1")),
        Arguments.argumentSet("minimumBuilds / 等于", MINIMUM_BUILD, ANDROID_175102, false, none),
        Arguments.argumentSet("minimumBuilds / 高于", MINIMUM_BUILD, ANDROID_175103, false, none),
        Arguments.argumentSet("minimumBuilds / UA 没带构建号：回到按版本判（这里没配版本规则）", MINIMUM_BUILD, ANDROID_NO_BUILD,
            false, none),
        Arguments.argumentSet("minimumBuilds / 构建号写坏了：当没有", MINIMUM_BUILD, ANDROID_BAD_BUILD, false, none),
        Arguments.argumentSet("minimumBuilds / 别的平台没配", MINIMUM_BUILD, IOS_0, false, none),
        Arguments.argumentSet("minimumBuilds / 认不出的 UA", MINIMUM_BUILD, UNRECOGNIZED, false, none),

        // blockedBuilds：同一个 versionName 的热修包分得出来
        Arguments.argumentSet("blockedBuilds / 命中", BLOCKED_BUILD, ANDROID_175101, true,
            List.of("android:blocked_build=1")),
        Arguments.argumentSet("blockedBuilds / 同版本号、另一个构建号不拦", BLOCKED_BUILD, ANDROID_175102, false, none),
        Arguments.argumentSet("blockedBuilds / 没带构建号不拦", BLOCKED_BUILD, ANDROID_NO_BUILD, false, none),
        Arguments.argumentSet("blockedBuilds / 构建号写坏了不拦", BLOCKED_BUILD, ANDROID_BAD_BUILD, false, none),

        // 两种配置同时存在：任一命中就拒；各记各的标签
        Arguments.argumentSet("版本 + 构建号都命中", BOTH_MINIMUMS, ANDROID_175101, true,
            List.of("android:expired=1", "android:expired_build=1")),
        Arguments.argumentSet("只有版本规则命中", BOTH_MINIMUMS, ANDROID_175102, true, List.of("android:expired=1")),
        Arguments.argumentSet("UA 没带构建号：回到按版本判，版本规则命中", BOTH_MINIMUMS, ANDROID_NO_BUILD, true,
            List.of("android:expired=1")),
        Arguments.argumentSet("构建号写坏了：回到按版本判，版本规则命中", BOTH_MINIMUMS, ANDROID_BAD_BUILD, true,
            List.of("android:expired=1")),
        Arguments.argumentSet("只有构建号规则命中", VERSION_PASSES_BUILD_FAILS, ANDROID_175101, true,
            List.of("android:expired_build=1")),
        Arguments.argumentSet("两条规则都过", VERSION_PASSES_BUILD_FAILS, ANDROID_175102, false, none),
        Arguments.argumentSet("老包没有构建号：构建号规则管不到它，版本规则又过得去 → 放行", VERSION_PASSES_BUILD_FAILS,
            ANDROID_NO_BUILD, false, none),
        Arguments.argumentSet("minimumBuilds 与 blockedBuilds 同时配：只命中封禁", MINIMUM_AND_BLOCKED, ANDROID_175101, true,
            List.of("android:blocked_build=1")),
        Arguments.argumentSet("minimumBuilds 与 blockedBuilds 同时配：都不命中", MINIMUM_AND_BLOCKED, ANDROID_175102, false,
            none),

        // iOS：构建号 0 是合法的；Desktop 没有 Build/ 段，构建号规则管不到它
        Arguments.argumentSet("iOS / 等于最低构建号", MINIMUM_ON_ALL_PLATFORMS, IOS_37, false, none),
        Arguments.argumentSet("iOS / 低于最低构建号", MINIMUM_ON_ALL_PLATFORMS, IOS_36, true,
            List.of("ios:expired_build=1")),
        Arguments.argumentSet("iOS / 构建号 0", MINIMUM_ON_ALL_PLATFORMS, IOS_0, true, List.of("ios:expired_build=1")),
        Arguments.argumentSet("Desktop 配了 minimumBuilds 但 UA 没有 Build/ 段：不拦", MINIMUM_ON_ALL_PLATFORMS, DESKTOP,
            false, none));
  }

  // ---- HTTP（499）----

  @ParameterizedTest
  @MethodSource("httpAndGrpc")
  void http(final String remoteDeprecationYaml, final String userAgent, final boolean expectDeprecation)
      throws IOException, ServletException {

    final RemoteDeprecationFilter filter = filter(remoteDeprecationYaml);

    final HttpServletRequest servletRequest = mock(HttpServletRequest.class);
    final HttpServletResponse servletResponse = mock(HttpServletResponse.class);
    final FilterChain filterChain = mock(FilterChain.class);

    when(servletRequest.getHeader(HttpHeaders.USER_AGENT)).thenReturn(userAgent);

    filter.doFilter(servletRequest, servletResponse, filterChain);

    if (expectDeprecation) {
      verify(filterChain, never()).doFilter(any(), any());
      verify(servletResponse).sendError(499);
    } else {
      verify(filterChain).doFilter(servletRequest, servletResponse);
      verify(servletResponse, never()).sendError(anyInt());
    }
  }

  // ---- gRPC（UPGRADE_REQUIRED）----

  @SuppressWarnings("DataFlowIssue")
  @ParameterizedTest
  @MethodSource("httpAndGrpc")
  void grpc(final String remoteDeprecationYaml, final String userAgentString, final boolean expectDeprecation)
      throws IOException, InterruptedException {

    final RemoteDeprecationFilter filter = filter(remoteDeprecationYaml);

    final MockRequestAttributesInterceptor mockRequestAttributesInterceptor = new MockRequestAttributesInterceptor();
    mockRequestAttributesInterceptor.setRequestAttributes(
        new RequestAttributes(InetAddresses.forString("127.0.0.1"), userAgentString, null));

    final Server testServer = InProcessServerBuilder.forName("RemoteDeprecationFilterBuildNumberTest")
        .directExecutor()
        .addService(new EchoServiceImpl())
        .intercept(filter)
        .intercept(mockRequestAttributesInterceptor)
        .build()
        .start();

    final ManagedChannel channel = InProcessChannelBuilder.forName("RemoteDeprecationFilterBuildNumberTest")
        .directExecutor()
        .userAgent(userAgentString)
        .build();

    try {
      final String echoString = "Test";

      final EchoServiceGrpc.EchoServiceBlockingStub client = EchoServiceGrpc.newBlockingStub(channel);
      final EchoRequest request = EchoRequest.newBuilder()
          .setPayload(ByteString.copyFromUtf8(echoString))
          .build();

      if (expectDeprecation) {
        final StatusRuntimeException e = assertThrows(StatusRuntimeException.class, () -> client.echo(request));
        final Status status = StatusProto.fromThrowable(e);
        final ErrorInfo errorInfo = assertDoesNotThrow(() -> status.getDetailsList().stream()
            .filter(any -> any.is(ErrorInfo.class)).findFirst()
            .orElseThrow(() -> new AssertionError("No error info found"))
            .unpack(ErrorInfo.class));

        assertEquals(GrpcExceptions.DOMAIN, errorInfo.getDomain());
        assertEquals(io.grpc.Status.Code.INVALID_ARGUMENT.value(), status.getCode());
        assertEquals("UPGRADE_REQUIRED", errorInfo.getReason());
      } else {
        assertEquals(echoString, client.echo(request).getPayload().toStringUtf8());
      }
    } finally {
      channel.shutdownNow();
      testServer.shutdownNow();
      testServer.awaitTermination();
    }
  }

  private static Stream<Arguments> httpAndGrpc() {
    return Stream.of(
        Arguments.argumentSet("无配置", NONE, ANDROID_175101, false),
        Arguments.argumentSet("minimumBuilds 低于", MINIMUM_BUILD, ANDROID_175101, true),
        Arguments.argumentSet("minimumBuilds 等于", MINIMUM_BUILD, ANDROID_175102, false),
        Arguments.argumentSet("minimumBuilds / 老包没有构建号", MINIMUM_BUILD, ANDROID_NO_BUILD, false),
        Arguments.argumentSet("blockedBuilds 命中", BLOCKED_BUILD, ANDROID_175101, true),
        Arguments.argumentSet("blockedBuilds 同版本号另一个构建号", BLOCKED_BUILD, ANDROID_175102, false),
        Arguments.argumentSet("版本规则命中 / 老包", BOTH_MINIMUMS, ANDROID_NO_BUILD, true),
        Arguments.argumentSet("iOS 构建号 0", MINIMUM_ON_ALL_PLATFORMS, IOS_0, true),
        Arguments.argumentSet("Desktop 没有构建号", MINIMUM_ON_ALL_PLATFORMS, DESKTOP, false),
        Arguments.argumentSet("认不出的 UA", MINIMUM_ON_ALL_PLATFORMS, UNRECOGNIZED, false));
  }

  // ---- 手滑的配置不能把请求路径变成 NPE ----

  @ParameterizedTest
  @MethodSource
  void aSloppyConfigurationNeverBreaksTheRequestPath(final String remoteDeprecationYaml) {
    final RemoteDeprecationFilter filter = filter(remoteDeprecationYaml);

    for (final String userAgent : List.of(ANDROID_175101, ANDROID_NO_BUILD, IOS_0, DESKTOP, UNRECOGNIZED)) {
      assertDoesNotThrow(() -> filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(userAgent), null),
          userAgent);
      assertThat(filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(userAgent), null))
          .as("a blank rule is an unset rule, so nobody is blocked: %s", userAgent).isFalse();
    }
  }

  private static Stream<Arguments> aSloppyConfigurationNeverBreaksTheRequestPath() {
    return Stream.of(
        Arguments.argumentSet("整块只有键", "remoteDeprecation:\n"),
        Arguments.argumentSet("minimumVersions 的值没写", "remoteDeprecation:\n  minimumVersions:\n    ANDROID:\n"),
        Arguments.argumentSet("blockedVersions 的元素没写",
            "remoteDeprecation:\n  blockedVersions:\n    ANDROID:\n      -\n"),
        Arguments.argumentSet("minimumBuilds 的值没写", "remoteDeprecation:\n  minimumBuilds:\n    ANDROID:\n    IOS:\n"),
        Arguments.argumentSet("blockedBuilds 的元素没写", "remoteDeprecation:\n  blockedBuilds:\n    ANDROID:\n      -\n"),
        Arguments.argumentSet("三个字段都只有键",
            "remoteDeprecation:\n  minimumVersions:\n  minimumBuilds:\n  blockedBuilds:\n"));
  }

  // ---- 指标：沿用现有 counter，新增标签值，不改已有的 ----

  @Test
  void buildRulesUseNewReasonValuesOnTheExistingCounter() {
    final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    final RemoteDeprecationFilter filter = filter("""
        remoteDeprecation:
          minimumBuilds:
            ANDROID: 175102
          blockedBuilds:
            IOS: [37]
        """);

    Metrics.addRegistry(registry);
    try {
      filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(ANDROID_175101), null);
      filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(ANDROID_175101), null);
      filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(IOS_37), null);
    } finally {
      Metrics.removeRegistry(registry);
    }

    assertThat(registry.get("chat.RemoteDeprecationFilter.deprecated")
        .tag("platform", "android").tag("reason", "expired_build").counter().count()).isEqualTo(2);
    assertThat(registry.get("chat.RemoteDeprecationFilter.deprecated")
        .tag("platform", "ios").tag("reason", "blocked_build").counter().count()).isEqualTo(1);

    // 已有的标签值一个都没动、也没被「顺带」记上
    assertThat(registry.find("chat.RemoteDeprecationFilter.deprecated").tag("reason", "expired").counters()).isEmpty();
    assertThat(registry.find("chat.RemoteDeprecationFilter.deprecated").tag("reason", "blocked").counters()).isEmpty();
    assertThat(registry.find("chat.RemoteDeprecationFilter.pendingDeprecation").meters()).isEmpty();
  }
}
