/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import java.net.InetAddress;
import java.util.Collection;
import java.util.List;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.util.InetAddressRange;

/// 按配置里的 CIDR 列表判定（`registrationRisk.datacenterNetworks`）。
///
/// 线性扫描：评估在后台线程上做，一次只多花几十微秒到零点几毫秒（列表几千条时），不在请求线程上。
/// 列表长到万级以后再换成排序区间 + 二分（接口不变）。
final class CidrSourceNetworkClassifier implements SourceNetworkClassifier {

  private final List<InetAddressRange> ranges;

  CidrSourceNetworkClassifier(final Collection<String> cidrBlocks) {
    this.ranges = cidrBlocks.stream().map(InetAddressRange::new).toList();
  }

  @Override
  public SourceNetwork classify(@Nullable final String sourceAddress) {
    final InetAddress address = RiskRules.parseAddress(sourceAddress).orElse(null);
    if (address == null) {
      return SourceNetwork.UNKNOWN;
    }
    for (final InetAddressRange range : ranges) {
      if (range.contains(address)) {
        return SourceNetwork.DATACENTER;
      }
    }
    return SourceNetwork.UNLISTED;
  }

  @Override
  public int networkCount() {
    return ranges.size();
  }
}
