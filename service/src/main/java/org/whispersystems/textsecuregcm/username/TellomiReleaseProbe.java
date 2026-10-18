/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.username;

import java.util.Set;
import java.util.UUID;

/// Tellomi（ADR-0066 §6.1；owner 2026-10-18 批准放宽这个账号的限流）：发版闸用的用户名探针账号。
///
/// 每次发版前 `scripts/release/username-probe-gate.sh` 用一个专门的测试号问一遍生产服务端：10 个保留词有没有人占（应
/// 没有）、保留它们会不会被拒（应 409）、保留一个普通名能不能成（应 200）。上游的两个限流——查名按 IP、保留按账号，
/// 都是桶 100、每 15 分钟回 1 个——一晚上发几版就被探针自己用光（2026-10-18 安卓上传因此等了 3 小时）。
///
/// 配在 `usernamePolicy.releaseProbeAccounts` 里的账号：保留用户名时用自己的限流 `tellomiUsernameProbe`，不占
/// `usernameReserve`；查名走只给它们开的 `GET /v1/tellomi/username-probe/{hash}`（同一个限流，按账号计），不占按 IP 的
/// `usernameLookup`。其他账号、匿名查名一律照上游；公开的查名接口仍然不接受登录。
public final class TellomiReleaseProbe {

  /// 没配探针账号（本地栈、测试、配置里没有这一项）。
  public static final TellomiReleaseProbe NONE = new TellomiReleaseProbe(Set.of());

  private final Set<UUID> accounts;

  public TellomiReleaseProbe(final Set<UUID> accounts) {
    this.accounts = Set.copyOf(accounts);
  }

  public boolean isProbe(final UUID accountIdentifier) {
    return accounts.contains(accountIdentifier);
  }

  public int size() {
    return accounts.size();
  }
}
