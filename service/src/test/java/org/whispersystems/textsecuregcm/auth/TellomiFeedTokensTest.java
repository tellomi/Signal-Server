/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.auth;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

import java.time.Instant;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class TellomiFeedTokensTest {

  private static final byte[] SIGNING_KEY = seq(0, 32);
  private static final byte[] PSEUDONYM_KEY = seq(100, 32);
  private static final Instant EXP = Instant.ofEpochSecond(1_760_000_000L);

  /// 对照向量：内容引擎（tellomi/content-engine 4483302）`auth.Sign` / `SignFriend` / `SignAudience` 用同样的
  /// 密钥（0x00..0x1f）、假名（0x00.. / 0x10.. / 0x20..，各 16 字节）和 exp 签出来的结果。逐字节相同 = 引擎一定验得过。
  private static final String ENGINE_CREDENTIAL = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R3IiwicmduIjoiY24iLCJleHAiOjE3NjAwMDAwMDB9.fBe1RxoGuuEYQxttOY8NEojzB2ZvOLzCqo20itIlA4c";
  private static final String ENGINE_FRIEND = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJ0ZWxsb21pLWZlZWQtZnJpZW5kIiwiZXhwIjoxNzYwMDAwMDAwLCJhIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsImIiOiJFQkVTRXhRVkZoY1lHUm9iSEIwZUh3Iiwib3AiOiJhZGQifQ.ZMHMaLVYpQU5muCkesBdegPrYoBJAAhFURMnmVoY9Fg";
  private static final String ENGINE_AUDIENCE = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0eXAiOiJ0ZWxsb21pLWZlZWQtYXVkaWVuY2UiLCJleHAiOjE3NjAwMDAwMDAsIm93bmVyIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsImtpbmQiOiJpbmNsdWRlIiwibWVtYmVycyI6WyJFQkVTRXhRVkZoY1lHUm9iSEIwZUh3IiwiSUNFaUl5UWxKaWNvS1NvckxDMHVMdyJdfQ.NakAEWCc1Cl0k-TK79zWaEhckKy4dnU2CxJR0vNSqC4";

  private static final UUID A = UUID.randomUUID();
  private static final UUID B = UUID.randomUUID();
  private static final UUID C = UUID.randomUUID();

  /// 假名是 HMAC 的输出，测试里换成固定字节，好和引擎的向量比
  private static final TellomiFeedTokens TOKENS = new TellomiFeedTokens(SIGNING_KEY, PSEUDONYM_KEY) {
    @Override
    public byte[] pseudonym(final UUID aci) {
      if (aci.equals(A)) {
        return seq(0, 16);
      }
      if (aci.equals(B)) {
        return seq(16, 16);
      }
      return seq(32, 16);
    }
  };

  @Test
  void matchesEngineCredential() {
    assertEquals(ENGINE_CREDENTIAL, TOKENS.credential(A, "cn", EXP));
  }

  @Test
  void matchesEngineFriendAssertion() {
    assertEquals(ENGINE_FRIEND, TOKENS.friendAssertion(A, B, "add", EXP));
  }

  @Test
  void matchesEngineAudienceList() {
    assertEquals(ENGINE_AUDIENCE, TOKENS.audienceList(A, "include", List.of(B, C), EXP));
  }

  @Test
  void pseudonymIsStableTruncatedHmac() {
    final TellomiFeedTokens tokens = new TellomiFeedTokens(SIGNING_KEY, PSEUDONYM_KEY);
    final UUID aci = UUID.fromString("9d0652a3-dcc3-4d11-975f-74d61598733f");
    assertEquals(16, tokens.pseudonym(aci).length);
    assertArrayEquals(tokens.pseudonym(aci), new TellomiFeedTokens(seq(7, 32), PSEUDONYM_KEY).pseudonym(aci),
        "the pseudonym does not depend on the signing key");
    assertNotEquals(Arrays.toString(tokens.pseudonym(aci)),
        Arrays.toString(new TellomiFeedTokens(SIGNING_KEY, seq(7, 32)).pseudonym(aci)));
    // HMAC-SHA256(key = 0x64..0x83, "9d0652a3-dcc3-4d11-975f-74d61598733f")[:16]
    assertEquals(PSEUDONYM_VECTOR, HexFormat.of().formatHex(tokens.pseudonym(aci)));
  }

  private static final String PSEUDONYM_VECTOR = "b0e89e2cc1c1596085a6b99bc4f4ae3c";

  private static byte[] seq(final int start, final int n) {
    final byte[] b = new byte[n];
    for (int i = 0; i < n; i++) {
      b[i] = (byte) (start + i);
    }
    return b;
  }
}
