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

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import java.util.Collections;
import java.util.List;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import javax.annotation.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.signal.chat.rpc.EchoRequest;
import org.slf4j.LoggerFactory;
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

  // ---- 「新旧行为对照」整张表，逐格（PR 描述里那张表的每一格都在这里被断言）----

  /// 表的列：9 种 User-Agent，顺序固定
  private static final List<String> MATRIX_USER_AGENTS = List.of(
      ANDROID_175101, ANDROID_175102, ANDROID_NO_BUILD, ANDROID_BAD_BUILD, IOS_37, IOS_36, IOS_0, DESKTOP,
      UNRECOGNIZED);

  private static final List<String> MATRIX_LABELS = List.of(
      "Android 175101", "Android 同版本号 175102", "Android 老包（无 Build/）", "Android 老包（坏 Build/）",
      "iOS 37", "iOS 36", "iOS 0", "Desktop", "认不出的 UA");

  /// 旧代码不认识 minimumBuilds / blockedBuilds——它们是未知键，被静默忽略（`SystemMapper` 关了 FAIL_ON_UNKNOWN_PROPERTIES）——
  /// 所以「旧」= 同一份配置去掉构建号字段之后的结果。去掉构建号字段后的配置在新旧代码上结果相同，由
  /// `RemoteDeprecationFilterCompatibilityTest` 逐格守着。
  private static final String ONLY_VERSION_0_1_3 = """
      remoteDeprecation:
        minimumVersions:
          ANDROID: 0.1.3
      """;

  private static final String ONLY_VERSION_0_1_0 = """
      remoteDeprecation:
        minimumVersions:
          ANDROID: 0.1.0
      """;

  private static final String PASS = "放";

  private static String blocked(final String... counters) {
    return "拦 " + String.join(" + ", counters);
  }

  private static String describe(final Outcome outcome) {
    return outcome.block() ? blocked(outcome.deprecated().toArray(String[]::new)) : PASS;
  }

  private record MatrixRow(String name, String yaml, String yamlWithoutBuildFields, List<String> before,
                           List<String> after) {
  }

  private static Stream<Arguments> theWholeComparisonTable() {
    final List<String> passEverything = Collections.nCopies(MATRIX_USER_AGENTS.size(), PASS);

    // 只有旧字段：新旧相同
    final List<String> versionsOnly = List.of(
        blocked("android:expired=1"), blocked("android:expired=1"), blocked("android:expired=1"),
        blocked("android:expired=1"), PASS, PASS, PASS, blocked("desktop:expired=1"), PASS);

    // 版本规则（0.1.3）对所有 0.1.2 的 Android 包都命中；构建号规则只对带有效构建号的那两个再多记一次 / 不多记
    final List<String> bothBefore = List.of(
        blocked("android:expired=1"), blocked("android:expired=1"), blocked("android:expired=1"),
        blocked("android:expired=1"), PASS, PASS, PASS, PASS, PASS);

    final List<String> bothAfter = List.of(
        blocked("android:expired=1", "android:expired_build=1"), blocked("android:expired=1"),
        blocked("android:expired=1"), blocked("android:expired=1"), PASS, PASS, PASS, PASS, PASS);

    final List<String> onlyAndroid175101Blocked = List.of(
        blocked("android:expired_build=1"), PASS, PASS, PASS, PASS, PASS, PASS, PASS, PASS);

    final List<MatrixRow> rows = List.of(
        new MatrixRow("无配置", NONE, NONE, passEverything, passEverything),
        new MatrixRow("只有旧字段 minimumVersions", VERSIONS_ONLY, VERSIONS_ONLY, versionsOnly, versionsOnly),
        new MatrixRow("minimumBuilds: {ANDROID: 175102}", MINIMUM_BUILD, NONE, passEverything,
            onlyAndroid175101Blocked),
        new MatrixRow("blockedBuilds: {ANDROID: [175101]}", BLOCKED_BUILD, NONE, passEverything,
            List.of(blocked("android:blocked_build=1"), PASS, PASS, PASS, PASS, PASS, PASS, PASS, PASS)),
        new MatrixRow("minimumVersions {ANDROID: 0.1.3} + minimumBuilds {ANDROID: 175102}", BOTH_MINIMUMS,
            ONLY_VERSION_0_1_3, bothBefore, bothAfter),
        new MatrixRow("minimumVersions {ANDROID: 0.1.0} + minimumBuilds {ANDROID: 175102}", VERSION_PASSES_BUILD_FAILS,
            ONLY_VERSION_0_1_0, passEverything, onlyAndroid175101Blocked),
        new MatrixRow("minimumBuilds {ANDROID: 175102, IOS: 37, DESKTOP: 5}", MINIMUM_ON_ALL_PLATFORMS, NONE,
            passEverything,
            List.of(blocked("android:expired_build=1"), PASS, PASS, PASS, PASS, blocked("ios:expired_build=1"),
                blocked("ios:expired_build=1"), PASS, PASS)));

    return rows.stream().flatMap(row -> IntStream.range(0, MATRIX_USER_AGENTS.size()).mapToObj(column ->
        Arguments.argumentSet(row.name() + " / " + MATRIX_LABELS.get(column), row.yaml(),
            row.yamlWithoutBuildFields(), MATRIX_USER_AGENTS.get(column), row.before().get(column),
            row.after().get(column))));
  }

  @ParameterizedTest
  @MethodSource
  void theWholeComparisonTable(final String yaml, final String yamlWithoutBuildFields, final String userAgent,
      final String expectedBefore, final String expectedAfter) {

    assertThat(describe(evaluate(yamlWithoutBuildFields, userAgent)))
        .as("before: what the old code did (the build fields did not exist, so they were ignored)")
        .isEqualTo(expectedBefore);

    assertThat(describe(evaluate(yaml, userAgent))).as("after").isEqualTo(expectedAfter);
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

  // ---- 日志：当前生效的规则 ----

  /// 配置热更之后，运维要能看到「服务现在到底按什么规则在判」：每个新的配置实例第一次被请求用到时记一行 INFO；
  /// 同一个实例不重复记；缺省配置（没有 remoteDeprecation 块）从不记。拼错键名留下的空规则也会在这一行里显出来
  @Test
  void theConfigurationInEffectIsLoggedOncePerNewInstanceAndNeverForTheDefault() {
    final ch.qos.logback.classic.Logger filterLogger =
        (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(RemoteDeprecationFilter.class);
    final ListAppender<ILoggingEvent> appender = new ListAppender<>();
    appender.start();
    filterLogger.addAppender(appender);
    filterLogger.setLevel(Level.INFO);

    try {
      final DynamicConfiguration noRules = parsedConfiguration(NONE);
      final DynamicConfiguration withRules = parsedConfiguration(MINIMUM_BUILD);
      final DynamicConfiguration reloaded = parsedConfiguration(BLOCKED_BUILD);
      final DynamicConfiguration typo = parsedConfiguration("remoteDeprecation:\n  minimumBuild:\n    ANDROID: 1\n");

      @SuppressWarnings("unchecked") final DynamicConfigurationManager<DynamicConfiguration> manager =
          mock(DynamicConfigurationManager.class);
      when(manager.getConfiguration())
          .thenReturn(noRules, noRules, withRules, withRules, withRules, reloaded, reloaded, typo, typo);

      final RemoteDeprecationFilter filter =
          new RemoteDeprecationFilter(mock(AccountsManager.class), mock(AccountAuthenticator.class), manager);

      for (int i = 0; i < 9; i++) {
        filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(ANDROID_175101), null);
      }

      assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).hasSize(3);
      assertThat(appender.list).extracting(ILoggingEvent::getLevel).containsOnly(Level.INFO);
      assertThat(appender.list.get(0).getFormattedMessage()).contains("minimumBuilds={ANDROID=175102}");
      assertThat(appender.list.get(1).getFormattedMessage()).contains("blockedBuilds={ANDROID=[175101]}");
      // 键名拼错（minimumBuild）：这块配置是空的，日志里一眼能看出来
      assertThat(appender.list.get(2).getFormattedMessage())
          .contains("minimumBuilds={}").contains("blockedBuilds={}").contains("minimumVersions={}");
    } finally {
      filterLogger.detachAppender(appender);
      filterLogger.setLevel(null);
    }
  }

  private static DynamicConfiguration parsedConfiguration(final String remoteDeprecationYaml) {
    return DynamicConfigurationManager
        .parseConfiguration(REQUIRED_CONFIG + remoteDeprecationYaml, DynamicConfiguration.class).orElseThrow();
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

    // 已有的标签值一个都没动、也没被「顺带」记上。按计数值断言，不按「有没有这个计数器」：
    // 同一个 JVM 里之前的用例建过的组合计数器，会以 0 值挂到新注册表上，存在与否取决于测试的执行顺序
    assertThat(totalCount(registry, "chat.RemoteDeprecationFilter.deprecated", "reason", "expired")).isZero();
    assertThat(totalCount(registry, "chat.RemoteDeprecationFilter.deprecated", "reason", "blocked")).isZero();
    assertThat(totalCount(registry, "chat.RemoteDeprecationFilter.pendingDeprecation", null, null)).isZero();
  }

  private static double totalCount(final SimpleMeterRegistry registry, final String meterName,
      @Nullable final String tagKey, @Nullable final String tagValue) {

    final io.micrometer.core.instrument.search.Search search = registry.find(meterName);

    return (tagKey == null ? search : search.tag(tagKey, tagValue)).counters().stream()
        .mapToDouble(Counter::count).sum();
  }
}
