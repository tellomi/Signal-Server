/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.username;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.usernames.Username;

/**
 * Tellomi: this reader has to agree with {@code policy-username-hashes} (libsignal fork, {@code rust/policy}) bit for
 * bit. If the two drift, nothing crashes — the filter simply answers "not reserved" for everything and the server
 * quietly starts accepting {@code admin.01} again.
 * <p>
 * So the fixture is not hand-made: {@code parity-denylist.bloom} was produced by the Rust generator from a lexicon
 * with the single term {@code parityreserved}, and the hashes below are computed here with libsignal's own
 * {@link Username}, exactly as a client would compute them. The test therefore exercises the whole chain —
 * Rust hashing, Rust Bloom insertion, file format, Java parsing, Java Bloom lookup.
 */
class UsernameHashDenylistTest {

  private static final String FIXTURE = "/username/parity-denylist.bloom";
  private static final long FIXTURE_LEXICON_VERSION = 2026092201L;

  private static UsernameHashDenylist fixture() throws Exception {
    try (var stream = UsernameHashDenylistTest.class.getResourceAsStream(FIXTURE)) {
      assertTrue(stream != null, FIXTURE + " is missing from the test resources");
      final Path tmp = Files.createTempFile("denylist", ".bloom");
      Files.write(tmp, stream.readAllBytes());
      return UsernameHashDenylist.load(tmp);
    }
  }

  private static byte[] hashOf(final String username) throws Exception {
    return new Username(username).getHash();
  }

  @Test
  void loadsTheGeneratorsHeader() throws Exception {
    final UsernameHashDenylist denylist = fixture();
    assertFalse(denylist.isEmpty());
    assertEquals(FIXTURE_LEXICON_VERSION, denylist.lexiconVersion());
  }

  /**
   * Every discriminator the generator enumerated for a non-core term (1..=999, zero padded to two digits the way
   * {@code Username::format_parts} does) must be found.
   */
  @ParameterizedTest
  @ValueSource(strings = {"parityreserved.01", "parityreserved.02", "parityreserved.10", "parityreserved.99",
      "parityreserved.100", "parityreserved.500", "parityreserved.999"})
  void reservedUsernamesAreFound(final String username) throws Exception {
    assertTrue(fixture().contains(hashOf(username)),
        username + " was enumerated by the generator but the reader did not find it");
  }

  /** Unrelated usernames must not be caught — a 1e-6 filter makes a collision here vanishingly unlikely. */
  @ParameterizedTest
  @ValueSource(strings = {"parityallowed.01", "xiaoming.42", "alice.10", "badminton.07", "parityreserve.01"})
  void ordinaryUsernamesAreNotFound(final String username) throws Exception {
    assertFalse(fixture().contains(hashOf(username)), username + " should not be on the denylist");
  }

  /** Outside the enumerated range: the documented boundary of this defence (ADR-0062 §5.4). */
  @Test
  void aDiscriminatorBeyondTheEnumeratedRangeIsNotCaught() throws Exception {
    assertFalse(fixture().contains(hashOf("parityreserved.123456")),
        "the server-side filter only covers the enumerated discriminators; the client engine covers the rest");
  }

  @Test
  void anEmptyDenylistRefusesNothing() throws Exception {
    final UsernameHashDenylist denylist = UsernameHashDenylist.empty();
    assertTrue(denylist.isEmpty());
    assertFalse(denylist.contains(hashOf("parityreserved.01")));
  }

  @Test
  void aTruncatedFileIsRejected(@TempDir final Path dir) throws Exception {
    final byte[] good = fixtureBytes();
    final Path file = dir.resolve("truncated.bloom");
    Files.write(file, Arrays.copyOf(good, good.length - 1));
    assertThrows(IOException.class, () -> UsernameHashDenylist.load(file));
  }

  @Test
  void theWrongMagicIsRejected(@TempDir final Path dir) throws Exception {
    final byte[] bytes = fixtureBytes();
    bytes[0] = 'X';
    final Path file = dir.resolve("wrong-magic.bloom");
    Files.write(file, bytes);
    assertThrows(IOException.class, () -> UsernameHashDenylist.load(file));
  }

  @Test
  void anUnsupportedFormatVersionIsRejected(@TempDir final Path dir) throws Exception {
    final byte[] bytes = fixtureBytes();
    ByteBuffer.wrap(bytes, 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(99);
    final Path file = dir.resolve("future.bloom");
    Files.write(file, bytes);
    assertThrows(IOException.class, () -> UsernameHashDenylist.load(file));
  }

  private static byte[] fixtureBytes() throws IOException {
    try (var stream = UsernameHashDenylistTest.class.getResourceAsStream(FIXTURE)) {
      return stream.readAllBytes();
    }
  }
}
