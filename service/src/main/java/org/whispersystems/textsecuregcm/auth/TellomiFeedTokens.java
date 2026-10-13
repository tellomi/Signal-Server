/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/// Tellomi（ADR-0071 §5.3）：内容引擎认的三种 HS256 JWT。格式由引擎的 `internal/engine/auth`（`Sign`、`SignFriend`、
/// `SignAudience`）定：头固定是 `{"alg":"HS256","typ":"JWT"}`（引擎逐字比对），claims 的字段和顺序照引擎，
/// 所以同样的输入签出来和引擎逐字节一样（见测试里的对照向量）。
///
/// 内容引擎只认假名：`sub = HMAC-SHA256(pseudonymKey, ACI 的 UUID 字符串)` 取前 16 字节，照 `DirectoryV2Controller`
/// 的 `withUserDerivationKey` 做法。ACI、手机号都不出 Signal-Server。
public class TellomiFeedTokens {

  public static final String TYP_FRIEND = "tellomi-feed-friend";
  public static final String TYP_AUDIENCE = "tellomi-feed-audience";
  public static final int PSEUDONYM_LENGTH = 16;

  private static final String ALGORITHM = "HmacSHA256";
  private static final Base64.Encoder B64 = Base64.getUrlEncoder().withoutPadding();
  private static final String HEADER = B64.encodeToString(
      "{\"alg\":\"HS256\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
  private static final ObjectMapper MAPPER = new ObjectMapper();

  private final byte[] signingKey;
  private final byte[] pseudonymKey;

  public TellomiFeedTokens(final byte[] signingKey, final byte[] pseudonymKey) {
    this.signingKey = signingKey.clone();
    this.pseudonymKey = pseudonymKey.clone();
  }

  /// 16 字节派生假名
  public byte[] pseudonym(final UUID aci) {
    return Arrays.copyOf(hmac(pseudonymKey, aci.toString().getBytes(StandardCharsets.UTF_8)), PSEUDONYM_LENGTH);
  }

  /// 动态凭证：`{sub, rgn, exp}`
  public String credential(final UUID aci, final String region, final Instant expiration) {
    return sign(new Credential(b64(pseudonym(aci)), region, expiration.getEpochSecond()));
  }

  /// 好友声明：`a` 说 `b` 是 / 不再是好友（`op` = add / remove）
  public String friendAssertion(final UUID a, final UUID b, final String op, final Instant expiration) {
    return sign(new Assertion(TYP_FRIEND, expiration.getEpochSecond(), b64(pseudonym(a)), b64(pseudonym(b)), op,
        null, null, null));
  }

  /// 受众名单：`owner` 的「部分可见」（include）或「不给谁看」（exclude）
  public String audienceList(final UUID owner, final String kind, final List<UUID> members, final Instant expiration) {
    return sign(new Assertion(TYP_AUDIENCE, expiration.getEpochSecond(), null, null, null,
        b64(pseudonym(owner)), kind, members.stream().map(m -> b64(pseudonym(m))).toList()));
  }

  @JsonPropertyOrder({"sub", "rgn", "exp"})
  private record Credential(String sub, String rgn, long exp) {
  }

  // 引擎按 DisallowUnknownFields + omitempty 解析：没有的字段不写
  @JsonInclude(JsonInclude.Include.NON_NULL)
  @JsonPropertyOrder({"typ", "exp", "a", "b", "op", "owner", "kind", "members"})
  private record Assertion(String typ, long exp, String a, String b, String op,
                           String owner, String kind, List<String> members) {
  }

  private String sign(final Object claims) {
    final byte[] body;
    try {
      body = MAPPER.writeValueAsBytes(claims);
    } catch (final JsonProcessingException e) {
      throw new AssertionError(e);
    }
    final String signing = HEADER + "." + B64.encodeToString(body);
    return signing + "." + B64.encodeToString(hmac(signingKey, signing.getBytes(StandardCharsets.US_ASCII)));
  }

  private static String b64(final byte[] bytes) {
    return B64.encodeToString(bytes);
  }

  private static byte[] hmac(final byte[] key, final byte[] input) {
    try {
      final Mac mac = Mac.getInstance(ALGORITHM);
      mac.init(new SecretKeySpec(key, ALGORITHM));
      return mac.doFinal(input);
    } catch (final NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }
}
