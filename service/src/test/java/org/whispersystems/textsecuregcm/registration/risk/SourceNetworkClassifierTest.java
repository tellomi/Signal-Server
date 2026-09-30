/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.whispersystems.textsecuregcm.registration.risk.SourceNetworkClassifier.SourceNetwork;

/// 「是否机房」的判定接口（ADR-0070 §6.1 第 2 条）：这一期只读配置里的网段列表，缺省为空
class SourceNetworkClassifierTest {

  @Test
  void anEmptyListMeansNothingIsListed() {
    final SourceNetworkClassifier classifier = SourceNetworkClassifier.fromCidrBlocks(List.of());

    assertThat(classifier.networkCount()).isZero();
    assertThat(classifier.classify("203.0.113.9")).isEqualTo(SourceNetwork.UNLISTED);
    assertThat(classifier.classify("2001:db8::1")).isEqualTo(SourceNetwork.UNLISTED);
  }

  @Test
  void listedNetworksAreDatacenters() {
    final SourceNetworkClassifier classifier =
        SourceNetworkClassifier.fromCidrBlocks(List.of("203.0.113.0/24", "198.51.100.128/25", "2001:db8::/32"));

    assertThat(classifier.networkCount()).isEqualTo(3);

    // 网段的第一个和最后一个地址都在里面，前一个和后一个不在
    assertThat(classifier.classify("203.0.113.0")).isEqualTo(SourceNetwork.DATACENTER);
    assertThat(classifier.classify("203.0.113.255")).isEqualTo(SourceNetwork.DATACENTER);
    assertThat(classifier.classify("203.0.112.255")).isEqualTo(SourceNetwork.UNLISTED);
    assertThat(classifier.classify("203.0.114.0")).isEqualTo(SourceNetwork.UNLISTED);

    assertThat(classifier.classify("198.51.100.127")).isEqualTo(SourceNetwork.UNLISTED);
    assertThat(classifier.classify("198.51.100.128")).isEqualTo(SourceNetwork.DATACENTER);
    assertThat(classifier.classify("198.51.100.255")).isEqualTo(SourceNetwork.DATACENTER);

    assertThat(classifier.classify("2001:db8:ffff::1")).isEqualTo(SourceNetwork.DATACENTER);
    assertThat(classifier.classify("2001:db9::1")).isEqualTo(SourceNetwork.UNLISTED);
  }

  @Test
  void addressFamiliesDoNotMix() {
    final SourceNetworkClassifier classifier = SourceNetworkClassifier.fromCidrBlocks(List.of("203.0.113.0/24"));

    assertThat(classifier.classify("2001:db8::cb00:7100")).isEqualTo(SourceNetwork.UNLISTED);
    // IPv4 映射的 IPv6 地址（双栈监听时可能出现）当作它背后的 IPv4 地址
    assertThat(classifier.classify("::ffff:203.0.113.9")).isEqualTo(SourceNetwork.DATACENTER);
  }

  @ParameterizedTest
  @NullAndEmptySource
  @ValueSource(strings = {" ", "example.com", "not an address", "203.0.113.0/24"})
  void anAddressThatCannotBeParsedIsUnknownNotDatacenterNorUnlisted(final String address) {
    assertThat(SourceNetworkClassifier.fromCidrBlocks(List.of("203.0.113.0/24")).classify(address))
        .isEqualTo(SourceNetwork.UNKNOWN);
  }

  @Test
  void aBadNetworkIsRejectedWhenTheClassifierIsBuilt() {
    assertThatThrownBy(() -> SourceNetworkClassifier.fromCidrBlocks(List.of("203.0.113.0")))
        .isInstanceOf(IllegalArgumentException.class);
  }
}
