/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.registration.risk;

/// 评估那一刻从计数里读出来的数（ADR-0070 §6.2 表里「自己计数」的那几行）。全是聚合数字，不带任何标识信息，可以放进日志和指标。
///
/// 「含这一次」的口径：建会话时先把这一次记进去再读，所以 `*Sessions24h` 包含当前这个会话；发码数、验证数是发码 / 验码成功之后才记，
/// 评估时读到的是「这一次之前」的。窗口都是按整点桶算的近似：24 小时 = 最近 24 个整点桶（实际覆盖 23–24 小时），
/// 1 小时 = 当前整点桶 + 上一个整点桶按剩余比例加权。
///
/// @param subnetSessions24h    同一网段（IPv4 /24、IPv6 /56）24 小时内建会话次数；来源地址解析不了时为 0
/// @param ipSessions24h        同一 IP 24 小时内建会话次数
/// @param numberSessions24h    同一号码 24 小时内建会话次数
/// @param numberCodes24h       同一号码 24 小时内已经发出的验证码条数
/// @param prefixSent1h         同一号段（前 7 位）最近一小时发码数
/// @param prefixVerified1h     同一号段最近一小时验证成功数
/// @param wouldAllowThisHour   全局本整点小时里「本来会放行」的会话数（放行预算的已用量）
/// @param cohortSent1h         「本来会放行」那一组会话最近一小时的发码数
/// @param cohortVerified1h     这一组会话最近一小时验证成功数
public record RiskSnapshot(long subnetSessions24h,
                           long ipSessions24h,
                           long numberSessions24h,
                           long numberCodes24h,
                           long prefixSent1h,
                           long prefixVerified1h,
                           long wouldAllowThisHour,
                           long cohortSent1h,
                           long cohortVerified1h) {
}
