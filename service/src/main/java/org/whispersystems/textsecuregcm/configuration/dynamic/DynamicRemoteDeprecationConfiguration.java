/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration.dynamic;

import com.vdurmont.semver4j.Semver;
import jakarta.validation.constraints.NotNull;
import java.util.Collections;
import java.util.EnumMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.util.ua.ClientPlatform;

/// 远程弃用配置：按平台拒绝太旧 / 被封的客户端（HTTP 499、gRPC `UPGRADE_REQUIRED`）。全部缺省为空 = 什么都不拦。
///
/// Tellomi（tellomi/tellomi#1399）在末尾加了两个可选字段 `minimumBuilds` / `blockedBuilds`：按构建号（User-Agent 里的 `Build/` 段）拒绝，
/// 同一个 versionName 的热修包分得出来；UA 没带构建号（Desktop、老包）的请求不受它们影响，照旧只按版本判。
/// 老的六参构造方法保留，老配置、老测试照常用。
///
/// 这份配置可以在线热更，所以**手滑写出来的东西不能把请求路径变成 NPE**：
/// 只写了键没写值（`ANDROID:`）得到的 null 值 / null 元素，一律当「没设」丢掉（所以「把值删了、留着键」也能撤掉一条规则），
/// 每丢一项记一条 WARN（以前这是请求路径上的 NPE，会大声失败；现在不能悄悄地失败）。
public record DynamicRemoteDeprecationConfiguration(
    @NotNull Map<ClientPlatform, Semver> minimumVersions,
    @NotNull Map<ClientPlatform, Semver> versionsPendingDeprecation,
    @NotNull Map<ClientPlatform, Set<Semver>> blockedVersions,
    @NotNull Map<ClientPlatform, Set<Semver>> versionsPendingBlock,
    @NotNull Boolean spqrEnforcementPending,
    @NotNull Boolean requireSpqr,
    // Tellomi：构建号小于它的拒绝（按平台）
    @NotNull Map<ClientPlatform, Long> minimumBuilds,
    // Tellomi：紧急封掉的构建号（按平台）
    @NotNull Map<ClientPlatform, Set<Long>> blockedBuilds) {

  private static final Logger log = LoggerFactory.getLogger(DynamicRemoteDeprecationConfiguration.class);

  public static DynamicRemoteDeprecationConfiguration DEFAULT = new DynamicRemoteDeprecationConfiguration(
      Collections.emptyMap(),
      Collections.emptyMap(),
      Collections.emptyMap(),
      Collections.emptyMap(),
      false,
      false,
      Collections.emptyMap(),
      Collections.emptyMap());

  /// 改动前的六参签名：新字段缺省为空
  public DynamicRemoteDeprecationConfiguration(
      final Map<ClientPlatform, Semver> minimumVersions,
      final Map<ClientPlatform, Semver> versionsPendingDeprecation,
      final Map<ClientPlatform, Set<Semver>> blockedVersions,
      final Map<ClientPlatform, Set<Semver>> versionsPendingBlock,
      final Boolean spqrEnforcementPending,
      final Boolean requireSpqr) {

    this(minimumVersions, versionsPendingDeprecation, blockedVersions, versionsPendingBlock, spqrEnforcementPending,
        requireSpqr, null, null);
  }

  public DynamicRemoteDeprecationConfiguration {
    if (minimumVersions == null) {
      minimumVersions = DEFAULT.minimumVersions();
    }

    if (versionsPendingDeprecation == null) {
      versionsPendingDeprecation = DEFAULT.versionsPendingDeprecation();
    }

    if (blockedVersions == null) {
      blockedVersions = DEFAULT.blockedVersions();
    }

    if (versionsPendingBlock == null) {
      versionsPendingBlock = DEFAULT.versionsPendingBlock();
    }

    if (spqrEnforcementPending == null) {
      spqrEnforcementPending = DEFAULT.spqrEnforcementPending();
    }

    if (requireSpqr == null) {
      requireSpqr = DEFAULT.requireSpqr();
    }

    if (minimumBuilds == null) {
      minimumBuilds = DEFAULT.minimumBuilds();
    }

    if (blockedBuilds == null) {
      blockedBuilds = DEFAULT.blockedBuilds();
    }

    // Tellomi：空值当「没设」丢掉，并让配置对象不可变（它被所有请求线程共享）
    minimumVersions = withoutNullValues("minimumVersions", minimumVersions);
    versionsPendingDeprecation = withoutNullValues("versionsPendingDeprecation", versionsPendingDeprecation);
    blockedVersions = withoutNullElements("blockedVersions", blockedVersions);
    versionsPendingBlock = withoutNullElements("versionsPendingBlock", versionsPendingBlock);
    minimumBuilds = requireNonNegative("minimumBuilds", withoutNullValues("minimumBuilds", minimumBuilds));
    blockedBuilds =
        requireNonNegativeElements("blockedBuilds", withoutNullElements("blockedBuilds", blockedBuilds));
  }

  private static <V> Map<ClientPlatform, V> withoutNullValues(final String fieldName,
      final Map<ClientPlatform, V> map) {

    final Map<ClientPlatform, V> copy = new EnumMap<>(ClientPlatform.class);

    map.forEach((platform, value) -> {
      if (platform == null) {
        return;
      }

      if (value == null) {
        log.warn("remoteDeprecation.{}.{} has no value; treating it as not set", fieldName, platform);
        return;
      }

      copy.put(platform, value);
    });

    return Collections.unmodifiableMap(copy);
  }

  private static <E> Map<ClientPlatform, Set<E>> withoutNullElements(final String fieldName,
      final Map<ClientPlatform, Set<E>> map) {

    final Map<ClientPlatform, Set<E>> copy = new EnumMap<>(ClientPlatform.class);

    map.forEach((platform, elements) -> {
      if (platform == null) {
        return;
      }

      if (elements == null) {
        log.warn("remoteDeprecation.{}.{} has no value; treating it as not set", fieldName, platform);
        return;
      }

      if (elements.stream().anyMatch(Objects::isNull)) {
        log.warn("remoteDeprecation.{}.{} contains an empty list item; ignoring it", fieldName, platform);
      }

      copy.put(platform, elements.stream().filter(Objects::nonNull).collect(Collectors.toUnmodifiableSet()));
    });

    return Collections.unmodifiableMap(copy);
  }

  private static Map<ClientPlatform, Long> requireNonNegative(final String fieldName,
      final Map<ClientPlatform, Long> builds) {

    builds.forEach((platform, build) -> requireNonNegative(fieldName, platform, build));

    return builds;
  }

  private static Map<ClientPlatform, Set<Long>> requireNonNegativeElements(final String fieldName,
      final Map<ClientPlatform, Set<Long>> builds) {

    builds.forEach((platform, platformBuilds) ->
        platformBuilds.forEach(build -> requireNonNegative(fieldName, platform, build)));

    return builds;
  }

  private static void requireNonNegative(final String fieldName, final ClientPlatform platform, final long build) {
    if (build < 0) {
      throw new IllegalArgumentException(
          "remoteDeprecation.%s.%s must not be negative: %d".formatted(fieldName, platform, build));
    }
  }
}
