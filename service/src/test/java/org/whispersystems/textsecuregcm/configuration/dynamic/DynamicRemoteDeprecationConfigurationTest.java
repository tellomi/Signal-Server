/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration.dynamic;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.vdurmont.semver4j.Semver;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;

/// tellomi/tellomi#1399：`remoteDeprecation.minimumBuilds` / `blockedBuilds` 两个可选字段的解析与校验，
/// 以及「配置能在线改」之后，手滑写出来的空值 / 空块不能变成请求路径上的 NPE。
/// 全部走真实的解析入口（`DynamicConfigurationManager.parseConfiguration`：YAML → `DynamicConfiguration` → Bean Validation）。
class DynamicRemoteDeprecationConfigurationTest {

  private static final String REQUIRED_CONFIG = """
      captcha:
        scoreFloor: 1.0
      """;

  private ListAppender<ILoggingEvent> logAppender;
  private ch.qos.logback.classic.Logger recordLogger;

  @BeforeEach
  void attachLogAppender() {
    recordLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(DynamicRemoteDeprecationConfiguration.class);
    recordLogger.setLevel(Level.DEBUG);
    logAppender = new ListAppender<>();
    logAppender.start();
    recordLogger.addAppender(logAppender);
  }

  @AfterEach
  void detachLogAppender() {
    recordLogger.detachAppender(logAppender);
    recordLogger.setLevel(null);
  }

  private List<String> warnings() {
    return logAppender.list.stream()
        .filter(event -> event.getLevel() == Level.WARN)
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }

  private static Optional<DynamicConfiguration> parse(final String remoteDeprecationYaml) {
    return DynamicConfigurationManager.parseConfiguration(REQUIRED_CONFIG + remoteDeprecationYaml,
        DynamicConfiguration.class);
  }

  private static DynamicRemoteDeprecationConfiguration parseRemoteDeprecation(final String remoteDeprecationYaml) {
    return parse(remoteDeprecationYaml).orElseThrow(
        () -> new AssertionError("should have parsed: " + remoteDeprecationYaml)).getRemoteDeprecationConfiguration();
  }

  @Test
  void noBuildFieldsMeansEmptyMaps() {
    final DynamicRemoteDeprecationConfiguration configuration = parseRemoteDeprecation("""
        remoteDeprecation:
          minimumVersions:
            IOS: 1.2.3
            ANDROID: 4.5.6
          versionsPendingDeprecation:
            DESKTOP: 7.8.9
          blockedVersions:
            DESKTOP:
              - 1.4.0-beta.2
          requireSpqr: true
        """);

    // 老配置照常解析，值和改动前一样
    assertThat(configuration.minimumVersions())
        .isEqualTo(Map.of(ClientPlatform.IOS, new Semver("1.2.3"), ClientPlatform.ANDROID, new Semver("4.5.6")));
    assertThat(configuration.versionsPendingDeprecation())
        .isEqualTo(Map.of(ClientPlatform.DESKTOP, new Semver("7.8.9")));
    assertThat(configuration.blockedVersions())
        .isEqualTo(Map.of(ClientPlatform.DESKTOP, Set.of(new Semver("1.4.0-beta.2"))));
    assertThat(configuration.versionsPendingBlock()).isEmpty();
    assertThat(configuration.requireSpqr()).isTrue();
    assertThat(configuration.spqrEnforcementPending()).isFalse();

    // 新字段缺省为空
    assertThat(configuration.minimumBuilds()).isEmpty();
    assertThat(configuration.blockedBuilds()).isEmpty();
  }

  @Test
  void noRemoteDeprecationBlockMeansTheDefault() {
    final DynamicRemoteDeprecationConfiguration configuration = parse("test: true\n").orElseThrow()
        .getRemoteDeprecationConfiguration();

    assertThat(configuration).isEqualTo(DynamicRemoteDeprecationConfiguration.DEFAULT);
    assertThat(configuration.minimumBuilds()).isEmpty();
    assertThat(configuration.blockedBuilds()).isEmpty();
  }

  @Test
  void buildFieldsParse() {
    final DynamicRemoteDeprecationConfiguration configuration = parseRemoteDeprecation("""
        remoteDeprecation:
          minimumBuilds:
            ANDROID: 175101
            IOS: 37
          blockedBuilds:
            ANDROID:
              - 175090
              - 175091
            IOS: [0]
        """);

    assertThat(configuration.minimumBuilds())
        .isEqualTo(Map.of(ClientPlatform.ANDROID, 175101L, ClientPlatform.IOS, 37L));
    assertThat(configuration.blockedBuilds()).isEqualTo(
        Map.of(ClientPlatform.ANDROID, Set.of(175090L, 175091L), ClientPlatform.IOS, Set.of(0L)));

    // 版本字段不受影响
    assertThat(configuration.minimumVersions()).isEmpty();
    assertThat(configuration.blockedVersions()).isEmpty();
  }

  @Test
  void buildFieldsAndVersionFieldsCanBeMixed() {
    final DynamicRemoteDeprecationConfiguration configuration = parseRemoteDeprecation("""
        remoteDeprecation:
          minimumVersions:
            DESKTOP: 0.1.11
          minimumBuilds:
            ANDROID: 175101
          blockedVersions:
            DESKTOP: [8.0.0-beta.2]
          blockedBuilds:
            ANDROID: [175090]
        """);

    assertThat(configuration.minimumVersions()).isEqualTo(Map.of(ClientPlatform.DESKTOP, new Semver("0.1.11")));
    assertThat(configuration.minimumBuilds()).isEqualTo(Map.of(ClientPlatform.ANDROID, 175101L));
    assertThat(configuration.blockedVersions())
        .isEqualTo(Map.of(ClientPlatform.DESKTOP, Set.of(new Semver("8.0.0-beta.2"))));
    assertThat(configuration.blockedBuilds()).isEqualTo(Map.of(ClientPlatform.ANDROID, Set.of(175090L)));
  }

  @Test
  void zeroIsAValidBuildNumber() {
    // iOS 第一个 TestFlight 包的构建号就是 0
    final DynamicRemoteDeprecationConfiguration configuration = parseRemoteDeprecation("""
        remoteDeprecation:
          minimumBuilds:
            IOS: 0
          blockedBuilds:
            IOS: [0]
        """);

    assertThat(configuration.minimumBuilds()).isEqualTo(Map.of(ClientPlatform.IOS, 0L));
    assertThat(configuration.blockedBuilds()).isEqualTo(Map.of(ClientPlatform.IOS, Set.of(0L)));
  }

  /// 写错的值：整份配置被拒绝（上一份好的保留，见 `DynamicConfigurationManager`），而不是悄悄按「没有」处理
  @ParameterizedTest
  @MethodSource
  void badValuesAreRejected(final String remoteDeprecationYaml) {
    assertThat(parse(remoteDeprecationYaml)).isEmpty();
  }

  private static Stream<Arguments> badValuesAreRejected() {
    return Stream.of(
        Arguments.argumentSet("构建号不是数字", "remoteDeprecation:\n  minimumBuilds:\n    ANDROID: abc\n"),
        Arguments.argumentSet("构建号带后缀", "remoteDeprecation:\n  minimumBuilds:\n    ANDROID: 175101x\n"),
        Arguments.argumentSet("构建号超过 long",
            "remoteDeprecation:\n  minimumBuilds:\n    ANDROID: 99999999999999999999\n"),
        Arguments.argumentSet("构建号是负数", "remoteDeprecation:\n  minimumBuilds:\n    ANDROID: -1\n"),
        Arguments.argumentSet("平台名小写", "remoteDeprecation:\n  minimumBuilds:\n    android: 1\n"),
        Arguments.argumentSet("没有这个平台", "remoteDeprecation:\n  minimumBuilds:\n    WINDOWS: 1\n"),
        Arguments.argumentSet("minimumBuilds 写成列表", "remoteDeprecation:\n  minimumBuilds: [1, 2]\n"),
        Arguments.argumentSet("minimumBuilds 写成单个数", "remoteDeprecation:\n  minimumBuilds: 5\n"),
        Arguments.argumentSet("封禁的构建号不是数字", "remoteDeprecation:\n  blockedBuilds:\n    ANDROID: [abc]\n"),
        Arguments.argumentSet("封禁的构建号是负数", "remoteDeprecation:\n  blockedBuilds:\n    ANDROID: [-3]\n"),
        Arguments.argumentSet("封禁的构建号超过 long",
            "remoteDeprecation:\n  blockedBuilds:\n    ANDROID: [99999999999999999999]\n"),
        Arguments.argumentSet("blockedBuilds 里平台名小写", "remoteDeprecation:\n  blockedBuilds:\n    ios: [1]\n"),
        Arguments.argumentSet("blockedBuilds 的值不是列表", "remoteDeprecation:\n  blockedBuilds:\n    ANDROID: 175101\n"),
        Arguments.argumentSet("YAML 语法错", "remoteDeprecation:\n  minimumBuilds: {ANDROID: 1\n"));
  }

  /// 只写了键、没写值（`ANDROID:`）：YAML 里是 null。以前（版本字段）这会留在 Map 里，请求路径上 NPE，
  /// 那个平台的每个请求都 500；配置改成在线热更之后，这种手滑会立刻生效。
  /// 现在：空值 = 「这一项没设」，丢掉；这样「把值删了、留着键」也能撤掉一条规则
  @Test
  void aKeyWithoutAValueMeansUnset() {
    final DynamicRemoteDeprecationConfiguration configuration = parseRemoteDeprecation("""
        remoteDeprecation:
          minimumVersions:
            ANDROID:
            IOS: 1.2.3
          versionsPendingDeprecation:
            DESKTOP:
          blockedVersions:
            ANDROID:
              -
              - 1.0.0
          versionsPendingBlock:
            IOS: [ ]
          minimumBuilds:
            ANDROID:
            IOS: 37
          blockedBuilds:
            ANDROID:
              -
              - 175101
            IOS:
        """);

    assertThat(configuration.minimumVersions()).isEqualTo(Map.of(ClientPlatform.IOS, new Semver("1.2.3")));
    assertThat(configuration.versionsPendingDeprecation()).isEmpty();
    assertThat(configuration.blockedVersions())
        .as("the null element is dropped, the valid one stays")
        .isEqualTo(Map.of(ClientPlatform.ANDROID, Set.of(new Semver("1.0.0"))));
    assertThat(configuration.versionsPendingBlock()).isEqualTo(Map.of(ClientPlatform.IOS, Set.of()));
    assertThat(configuration.minimumBuilds()).isEqualTo(Map.of(ClientPlatform.IOS, 37L));
    assertThat(configuration.blockedBuilds()).isEqualTo(Map.of(ClientPlatform.ANDROID, Set.of(175101L)));

    assertThat(configuration.minimumVersions().values()).doesNotContainNull();
    assertThat(configuration.minimumBuilds().values()).doesNotContainNull();
  }

  /// 丢空值不能是悄悄的：以前这是请求路径上的 NPE（大声失败），现在每丢一项都要留一条 WARN，运维才看得到「这一项没生效」
  @Test
  void everyDroppedBlankEntryIsLoggedAsAWarning() {
    parseRemoteDeprecation("""
        remoteDeprecation:
          minimumVersions:
            ANDROID:
          versionsPendingDeprecation:
            DESKTOP:
          blockedVersions:
            ANDROID:
              -
              - 1.0.0
            IOS:
          minimumBuilds:
            ANDROID:
          blockedBuilds:
            ANDROID:
              -
              - 175101
        """);

    assertThat(warnings()).containsExactlyInAnyOrder(
        "remoteDeprecation.minimumVersions.ANDROID has no value; treating it as not set",
        "remoteDeprecation.versionsPendingDeprecation.DESKTOP has no value; treating it as not set",
        "remoteDeprecation.blockedVersions.ANDROID contains an empty list item; ignoring it",
        "remoteDeprecation.blockedVersions.IOS has no value; treating it as not set",
        "remoteDeprecation.minimumBuilds.ANDROID has no value; treating it as not set",
        "remoteDeprecation.blockedBuilds.ANDROID contains an empty list item; ignoring it");
  }

  @Test
  void nothingIsLoggedWhenNothingIsDropped() {
    parseRemoteDeprecation("""
        remoteDeprecation:
          minimumVersions:
            ANDROID: 1.0.0
          minimumBuilds:
            IOS: 37
          blockedBuilds:
            ANDROID: [175101]
        """);

    assertThat(warnings()).isEmpty();
  }

  @Test
  void aWholeFieldWithoutAValueMeansEmpty() {
    final DynamicRemoteDeprecationConfiguration configuration = parseRemoteDeprecation("""
        remoteDeprecation:
          minimumVersions:
          minimumBuilds:
          blockedBuilds:
        """);

    assertThat(configuration).isEqualTo(DynamicRemoteDeprecationConfiguration.DEFAULT);
  }

  /// 整块写了键、没写内容（`remoteDeprecation:`，比如把下面的子项全注释掉了）：解析出来是 null，
  /// 过滤器在每个请求上读它就是 NPE——热更之后一次手滑就是全站 500。现在等同于「没写」（缺省配置）
  @ParameterizedTest
  @MethodSource
  void aBlankRemoteDeprecationBlockIsTheDefault(final String yaml) {
    final DynamicConfiguration configuration = parse(yaml).orElseThrow();

    assertThat(configuration.getRemoteDeprecationConfiguration()).isNotNull()
        .isEqualTo(DynamicRemoteDeprecationConfiguration.DEFAULT);
  }

  private static Stream<Arguments> aBlankRemoteDeprecationBlockIsTheDefault() {
    return Stream.of(
        Arguments.argumentSet("只有键", "remoteDeprecation:\n"),
        Arguments.argumentSet("写了 null", "remoteDeprecation: null\n"),
        Arguments.argumentSet("写了 ~", "remoteDeprecation: ~\n"),
        Arguments.argumentSet("子项全被注释掉", "remoteDeprecation:\n  # minimumBuilds:\n  #   ANDROID: 175101\n"));
  }

  @Test
  void theOldSixArgumentConstructorStillWorks() {
    // 上游的测试（RemoteDeprecationFilterTest）用这个签名构造配置，必须继续能编译、能用
    final DynamicRemoteDeprecationConfiguration configuration = new DynamicRemoteDeprecationConfiguration(
        Map.of(ClientPlatform.ANDROID, new Semver("1.0.0")), Map.of(), Map.of(), Map.of(), false, true);

    assertThat(configuration.minimumVersions()).isEqualTo(Map.of(ClientPlatform.ANDROID, new Semver("1.0.0")));
    assertThat(configuration.requireSpqr()).isTrue();
    assertThat(configuration.minimumBuilds()).isEmpty();
    assertThat(configuration.blockedBuilds()).isEmpty();
  }

  @Test
  void nullArgumentsMeanEmpty() {
    final DynamicRemoteDeprecationConfiguration configuration =
        new DynamicRemoteDeprecationConfiguration(null, null, null, null, null, null, null, null);

    assertThat(configuration).isEqualTo(DynamicRemoteDeprecationConfiguration.DEFAULT);
  }

  @Test
  void theParsedConfigurationIsImmutable() {
    final DynamicRemoteDeprecationConfiguration configuration = parseRemoteDeprecation("""
        remoteDeprecation:
          minimumVersions:
            IOS: 1.2.3
          blockedVersions:
            ANDROID: [1.0.0]
          minimumBuilds:
            ANDROID: 175101
          blockedBuilds:
            ANDROID: [175090]
        """);

    // 配置对象在所有请求线程之间共享：谁也不能改它
    assertThatThrownBy(() -> configuration.minimumBuilds().put(ClientPlatform.IOS, 1L))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> configuration.blockedBuilds().get(ClientPlatform.ANDROID).add(1L))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> configuration.minimumVersions().put(ClientPlatform.IOS, new Semver("9.9.9")))
        .isInstanceOf(UnsupportedOperationException.class);
    assertThatThrownBy(() -> configuration.blockedVersions().get(ClientPlatform.ANDROID).add(new Semver("9.9.9")))
        .isInstanceOf(UnsupportedOperationException.class);
  }

  /// 文档性质的测试：`SystemMapper` 关掉了 FAIL_ON_UNKNOWN_PROPERTIES，动态配置里**拼错的键被静默忽略**
  /// （上游一直如此，不止这一块）。所以「校验通过」不等于「写的每一项都生效了」——
  /// 改完要看指标 / 日志确认，见 PR 描述。如果哪天上游改成严格解析，这个测试会提醒我们把流程文档一起改
  @Test
  void misspelledKeysAreSilentlyIgnored() {
    final DynamicRemoteDeprecationConfiguration typoInsideTheBlock = parseRemoteDeprecation("""
        remoteDeprecation:
          minimumBuild:
            ANDROID: 175101
        """);
    assertThat(typoInsideTheBlock).isEqualTo(DynamicRemoteDeprecationConfiguration.DEFAULT);

    final DynamicConfiguration typoInTheBlockName = parse("""
        remoteDeprecationn:
          minimumBuilds:
            ANDROID: 175101
        """).orElseThrow();
    assertThat(typoInTheBlockName.getRemoteDeprecationConfiguration())
        .isEqualTo(DynamicRemoteDeprecationConfiguration.DEFAULT);
  }

  @Test
  void theOtherConfigurationBlocksAreNotAffected() {
    final DynamicConfiguration configuration = parse("""
        remoteDeprecation:
          minimumBuilds:
            ANDROID: 1
        limits:
          rateLimitReset:
            bucketSize: 17
            permitRegenerationDuration: PT0.000004S
        """).orElseThrow();

    assertThat(configuration.getLimits()).containsKey("rateLimitReset");
    assertThat(configuration.getCaptchaConfiguration().getScoreFloor()).isEqualByComparingTo("1.0");
  }
}
