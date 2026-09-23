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
import java.security.MessageDigest;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.signal.libsignal.usernames.Username;

/**
 * Tellomi: this reader has to agree with {@code policy-username-hashes} (libsignal fork, {@code rust/policy}) byte for
 * byte. If the two drift, nothing crashes — lookups simply answer "not reserved" for everything and the server quietly
 * starts accepting {@code admin.01} again.
 * <p>
 * So the fixture is not hand-made: {@code parity-denylist.bin} was produced by the Rust generator from a lexicon with
 * the single term {@code parityreserved}, and the hashes below are computed here with libsignal's own
 * {@link Username}, exactly as a client would compute them. The test therefore exercises the whole chain — Rust
 * hashing, Rust sorting, file format, Java parsing, Java lookup.
 */
class UsernameHashDenylistTest {

  private static final String FIXTURE = "/username/parity-denylist.bin";
  private static final long FIXTURE_LEXICON_VERSION = 2026092301L;
  private static final int HEADER_BYTES = 56;

  private static UsernameHashDenylist fixture() throws Exception {
    final Path tmp = Files.createTempFile("denylist", ".bin");
    Files.write(tmp, fixtureBytes());
    return UsernameHashDenylist.load(tmp);
  }

  private static byte[] hashOf(final String username) throws Exception {
    return new Username(username).getHash();
  }

  @Test
  void loadsTheGeneratorsHeader() throws Exception {
    final UsernameHashDenylist denylist = fixture();
    assertFalse(denylist.isEmpty());
    assertEquals(FIXTURE_LEXICON_VERSION, denylist.lexiconVersion());
    assertEquals(99, denylist.highestDiscriminator());
    assertEquals(99, denylist.size(), "one nickname × discriminators 01–99");
  }

  /** Every discriminator the generator enumerated (01–99, zero padded the way {@code Username::format_parts} is). */
  @ParameterizedTest
  @ValueSource(strings = {"parityreserved.01", "parityreserved.02", "parityreserved.10", "parityreserved.57",
      "parityreserved.99", "ParityReserved.01"})
  void reservedUsernamesAreFound(final String username) throws Exception {
    assertTrue(fixture().contains(hashOf(username)),
        username + " was enumerated by the generator but the reader did not find it");
  }

  @ParameterizedTest
  @ValueSource(strings = {"parityallowed.01", "xiaoming.42", "alice.10", "badminton.07", "parityreserve.01"})
  void ordinaryUsernamesAreNotFound(final String username) throws Exception {
    assertFalse(fixture().contains(hashOf(username)), username + " should not be on the denylist");
  }

  /** Three or more digits: the documented boundary (ADR-0066 §六) — clients show such a discriminator in full. */
  @ParameterizedTest
  @ValueSource(strings = {"parityreserved.100", "parityreserved.123", "parityreserved.9999"})
  void threeOrMoreDigitsAreNotCaught(final String username) throws Exception {
    assertFalse(fixture().contains(hashOf(username)));
  }

  @Test
  void malformedLookupsAreNotFound() throws Exception {
    final UsernameHashDenylist denylist = fixture();
    assertFalse(denylist.contains(null));
    assertFalse(denylist.contains(new byte[31]));
    assertFalse(denylist.contains(Arrays.copyOf(hashOf("parityreserved.01"), 33)));
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
    assertRejected(dir, Arrays.copyOf(good, good.length - 1));
    assertRejected(dir, Arrays.copyOf(good, HEADER_BYTES - 1));
  }

  @Test
  void theWrongMagicIsRejected(@TempDir final Path dir) throws Exception {
    final byte[] bytes = fixtureBytes();
    bytes[0] = 'X';
    assertRejected(dir, bytes);
  }

  /** The old Bloom-filter file must not be half-read as the new format after a partial deploy. */
  @Test
  void theOldBloomFormatIsRejected(@TempDir final Path dir) throws Exception {
    final byte[] bytes = fixtureBytes();
    bytes[3] = 'B';
    assertRejected(dir, bytes);
  }

  @Test
  void anUnsupportedFormatVersionIsRejected(@TempDir final Path dir) throws Exception {
    final byte[] bytes = fixtureBytes();
    ByteBuffer.wrap(bytes, 4, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(99);
    assertRejected(dir, bytes);
  }

  @Test
  void aCountThatDisagreesWithTheBodyIsRejected(@TempDir final Path dir) throws Exception {
    final byte[] bytes = fixtureBytes();
    ByteBuffer.wrap(bytes, 20, 4).order(ByteOrder.LITTLE_ENDIAN).putInt(98);
    assertRejected(dir, bytes);
  }

  @Test
  void aCorruptedBodyIsRejectedByItsDigest(@TempDir final Path dir) throws Exception {
    final byte[] bytes = fixtureBytes();
    bytes[HEADER_BYTES + 5] ^= 0x01;
    assertRejected(dir, bytes);
  }

  /**
   * Swap two hashes and recompute the digest, so that only the ordering check can catch it — binary search would
   * otherwise silently miss entries.
   */
  @Test
  void anUnsortedBodyIsRejectedEvenWithAValidDigest(@TempDir final Path dir) throws Exception {
    final byte[] bytes = fixtureBytes();
    final byte[] first = Arrays.copyOfRange(bytes, HEADER_BYTES, HEADER_BYTES + 32);
    System.arraycopy(bytes, HEADER_BYTES + 32, bytes, HEADER_BYTES, 32);
    System.arraycopy(first, 0, bytes, HEADER_BYTES + 32, 32);
    final MessageDigest digest = MessageDigest.getInstance("SHA-256");
    digest.update(bytes, HEADER_BYTES, bytes.length - HEADER_BYTES);
    System.arraycopy(digest.digest(), 0, bytes, 24, 32);
    assertRejected(dir, bytes);
  }

  private static void assertRejected(final Path dir, final byte[] bytes) throws IOException {
    final Path file = Files.createTempFile(dir, "bad", ".bin");
    Files.write(file, bytes);
    assertThrows(IOException.class, () -> UsernameHashDenylist.load(file));
  }

  private static byte[] fixtureBytes() throws IOException {
    try (var stream = UsernameHashDenylistTest.class.getResourceAsStream(FIXTURE)) {
      assertTrue(stream != null, FIXTURE + " is missing from the test resources");
      return stream.readAllBytes();
    }
  }
}
