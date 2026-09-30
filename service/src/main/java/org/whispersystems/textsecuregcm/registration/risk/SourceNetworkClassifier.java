/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

import java.util.Collection;
import javax.annotation.Nullable;

/// 「来源是不是机房 / 云厂商网段」的判定接口（ADR-0070 §6.1 第 2 条、§6.2 第 2 行）。
///
/// 这一期的实现（[CidrSourceNetworkClassifier]）只读配置里的网段列表，缺省为空；数据从哪来（DB-IP ASN Lite、IPtoASN、
/// ipverse、云厂商自己公布的网段……）和许可证要等 owner 拍板。以后换成「IP → ASN → 机房名单」或别的数据源，只需要换一个
/// 实现，评估器不用动。
public interface SourceNetworkClassifier {

  /// @param tag 指标标签
  enum SourceNetwork {
    /// 在机房 / 云厂商名单里：一律不放行（用 VPN 的人通常也从机房 IP 出来，他们只是出验证页，不是被拒）
    DATACENTER("datacenter"),
    /// 不在名单里（不等于「一定是住宅网络」：名单为空时所有来源都是这一类）
    UNLISTED("unlisted"),
    /// 来源地址缺失或解析不了：不知道它是不是机房，所以也不放行
    UNKNOWN("unknown");

    private final String tag;

    SourceNetwork(final String tag) {
      this.tag = tag;
    }

    public String tag() {
      return tag;
    }
  }

  /// 不抛异常；解析不了的地址返回 [SourceNetwork#UNKNOWN]
  SourceNetwork classify(@Nullable String sourceAddress);

  /// 名单里有多少个网段（指标里的 gauge：0 = 「机房」这一条恒成立，收到的数据要按这个读）
  int networkCount();

  static SourceNetworkClassifier fromCidrBlocks(final Collection<String> cidrBlocks) {
    return new CidrSourceNetworkClassifier(cidrBlocks);
  }
}
