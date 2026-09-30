/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.filters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.vdurmont.semver4j.Semver;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.auth.AccountAuthenticator;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicRemoteDeprecationConfiguration;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;
import org.whispersystems.textsecuregcm.util.ua.UserAgentUtil;

/// 特征化测试：「没配构建号规则」时，`RemoteDeprecationFilter.shouldBlock` 的判定和指标必须与改动前**逐项一致**
/// （tellomi/tellomi#1399：按构建号拒绝是新增的、缺省关闭的能力）。
///
/// 做法：同一批 User-Agent（含三端现在真实发的三种形状、老包、带坏 `Build/` 段的、无法识别的）× 五份只用**老字段**
/// 构造的配置（缺省空配置、只有最低版本、只有封禁版本、只有「即将弃用 / 封禁」的观察项、全都有），
/// 对每一格记下 `shouldBlock` 的返回值和 `deprecated` / `pendingDeprecation` 两个计数器的增量。
/// 期望值（`RemoteDeprecationFilterCompatibilityTest.baseline.txt`）是在**改动前的代码**上生成的；这个测试在改动前后都必须通过。
///
/// 这里只用改动前就存在的 API（六个参数的构造方法、`shouldBlock`），所以它能在改动前的代码上原样编译、运行。
class RemoteDeprecationFilterCompatibilityTest {

  /// 与本类同包的资源（src/test/resources/org/whispersystems/textsecuregcm/filters/）
  static final String BASELINE_RESOURCE = "RemoteDeprecationFilterCompatibilityTest.baseline.txt";

  /// `null` 与空串走「无法识别」的路径；其余是真实形状和各种怪形状
  static final List<String> USER_AGENTS = Arrays.asList(
      null,
      "",
      "Unrecognized UA",
      "curl/8.0.1",
      // 三端现在真实发的形状（取自各客户端 fork 的源码与测试）
      "Signal-Android/0.1.2 Android/34 Build/175101",
      "Signal-iOS/0.1.2 iOS/26.0 Build/37",
      "Signal-iOS/0.1.0 iOS/26.0 Build/0",
      "Signal-Desktop/0.1.10 macOS 25.0.0",
      "Signal-Desktop/0.1.10 Windows 10.0.22000",
      // 老包：没有 Build/ 段
      "Signal-Android/0.1.2 Android/34",
      "Signal-Android/0.0.9 Android/34 Build/100",
      "Signal-iOS/0.1.2 iOS/26.0",
      "Signal-Desktop/0.1.10",
      "Signal-Android/4.68.3",
      "Signal-iOS/3.9.0 (iPhone; iOS 12.2; Scale/3.00)",
      // iOS 早期的四段版本号（`<三段>.<构建号>`）：semver4j 3.1.0 宽松解析成 iOS / 0.1.x（第四段被丢掉），而且比较不可靠
      // （实测 `0.1.2.37` 与 `0.1.2` 互相「更低」）。这里只把现状钉住，不代表这是期望行为
      "Signal-iOS/0.1.0.37 iOS/26.0",
      "Signal-iOS/0.1.2.37 iOS/26.0",
      // Desktop 的 beta：配置里封了 8.0.0-beta.2，观察 8.0.0-beta.3
      "Signal-Desktop/8.0.0-beta.2",
      "Signal-Desktop/8.0.0-beta.3",
      // 坏的 / 怪的 Build/ 段
      "Signal-Android/0.1.2 Android/34 Build/abc",
      "Signal-Android/0.1.2 Android/34 Build/99999999999999999999",
      "Signal-Android/0.1.2 Build/175101 Android/34");

  /// 名字 → 配置。全部用改动前就有的六参构造方法
  static Map<String, DynamicRemoteDeprecationConfiguration> configurations() {
    final Map<String, DynamicRemoteDeprecationConfiguration> configurations = new LinkedHashMap<>();

    configurations.put("default", DynamicRemoteDeprecationConfiguration.DEFAULT);

    configurations.put("minimumVersionsOnly", new DynamicRemoteDeprecationConfiguration(
        new EnumMap<>(Map.of(
            ClientPlatform.ANDROID, new Semver("0.1.2"),
            ClientPlatform.IOS, new Semver("0.1.2"),
            ClientPlatform.DESKTOP, new Semver("0.1.10"))),
        Map.of(), Map.of(), Map.of(), false, false));

    configurations.put("blockedVersionsOnly", new DynamicRemoteDeprecationConfiguration(
        Map.of(), Map.of(),
        new EnumMap<>(Map.of(
            ClientPlatform.ANDROID, Set.of(new Semver("0.1.2")),
            ClientPlatform.IOS, Set.of(new Semver("0.1.0")),
            ClientPlatform.DESKTOP, Set.of(new Semver("8.0.0-beta.2")))),
        Map.of(), false, false));

    configurations.put("pendingOnly", new DynamicRemoteDeprecationConfiguration(
        Map.of(),
        new EnumMap<>(Map.of(
            ClientPlatform.ANDROID, new Semver("0.2.0"),
            ClientPlatform.IOS, new Semver("0.2.0"),
            ClientPlatform.DESKTOP, new Semver("0.2.0"))),
        Map.of(),
        new EnumMap<>(Map.of(ClientPlatform.DESKTOP, Set.of(new Semver("8.0.0-beta.3")))),
        false, false));

    configurations.put("allVersionFields", new DynamicRemoteDeprecationConfiguration(
        new EnumMap<>(Map.of(
            ClientPlatform.ANDROID, new Semver("1.0.0"),
            ClientPlatform.IOS, new Semver("1.0.0"),
            ClientPlatform.DESKTOP, new Semver("1.0.0"))),
        new EnumMap<>(Map.of(
            ClientPlatform.ANDROID, new Semver("1.1.0"),
            ClientPlatform.IOS, new Semver("1.1.0"),
            ClientPlatform.DESKTOP, new Semver("1.1.0"))),
        new EnumMap<>(Map.of(ClientPlatform.DESKTOP, Set.of(new Semver("8.0.0-beta.2")))),
        new EnumMap<>(Map.of(ClientPlatform.DESKTOP, Set.of(new Semver("8.0.0-beta.3")))),
        false, false));

    return configurations;
  }

  private static RemoteDeprecationFilter filterFor(final DynamicRemoteDeprecationConfiguration configuration) {
    final DynamicConfiguration dynamicConfiguration = mock(DynamicConfiguration.class);
    when(dynamicConfiguration.getRemoteDeprecationConfiguration()).thenReturn(configuration);

    @SuppressWarnings("unchecked") final DynamicConfigurationManager<DynamicConfiguration> dynamicConfigurationManager =
        mock(DynamicConfigurationManager.class);
    when(dynamicConfigurationManager.getConfiguration()).thenReturn(dynamicConfiguration);

    return new RemoteDeprecationFilter(mock(AccountsManager.class), mock(AccountAuthenticator.class),
        dynamicConfigurationManager);
  }

  /// 一格的结果：`config | ua | block=… | deprecated=… | pending=…`。计数器只列增量大于 0 的，按名字排序
  static String render(final String configurationName, final DynamicRemoteDeprecationConfiguration configuration,
      final String userAgentString) {

    final RemoteDeprecationFilter filter = filterFor(configuration);
    final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    final boolean block;

    Metrics.addRegistry(registry);
    try {
      block = filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(userAgentString), null);
    } finally {
      Metrics.removeRegistry(registry);
    }

    return "%s | %s | block=%s | deprecated=%s | pending=%s".formatted(
        configurationName,
        userAgentString == null ? "<null>" : "'" + userAgentString + "'",
        block,
        counters(registry, "chat.RemoteDeprecationFilter.deprecated"),
        counters(registry, "chat.RemoteDeprecationFilter.pendingDeprecation"));
  }

  private static String counters(final SimpleMeterRegistry registry, final String meterName) {
    return registry.find(meterName).meters().stream()
        .filter(meter -> meter instanceof Counter counter && counter.count() > 0)
        .map(meter -> meter.getId().getTags().stream()
            .map(tag -> tag.getKey() + "=" + tag.getValue())
            .sorted()
            .collect(Collectors.joining(",")) + "=" + (long) ((Counter) meter).count())
        .sorted()
        .collect(Collectors.joining(";", "[", "]"));
  }

  /// 全部格子（供基线生成器和本测试共用）
  static List<String> renderAll() {
    final List<String> lines = new ArrayList<>();

    configurations().forEach((name, configuration) ->
        USER_AGENTS.forEach(userAgent -> lines.add(render(name, configuration, userAgent))));

    return lines;
  }

  @Test
  void behaviourWithoutBuildRulesIsIdenticalToBeforeTheChange() throws IOException {
    final List<String> expected;

    try (final InputStream inputStream = getClass().getResourceAsStream(BASELINE_RESOURCE)) {
      assertThat(inputStream).as("baseline resource " + BASELINE_RESOURCE).isNotNull();
      expected = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8).lines().toList();
    }

    assertThat(renderAll()).containsExactlyElementsOf(expected);
  }

  /// 「没有配置」：空配置下，三端真实 UA、老包、坏 UA……一个都不拦，也不产生任何计数
  @Test
  void emptyConfigurationNeverBlocksAndNeverCounts() {
    USER_AGENTS.forEach(userAgent ->
        assertThat(render("default", DynamicRemoteDeprecationConfiguration.DEFAULT, userAgent))
            .as("User-Agent %s", userAgent)
            .endsWith("| block=false | deprecated=[] | pending=[]"));
  }
}
