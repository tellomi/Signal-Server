/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.username;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tellomi: reserved / brand / impersonation usernames, as the exact list of their hashes.
 * <p>
 * The server never sees a username in the clear — clients reserve {@code Username::hash()} and that is all we store —
 * so the only way to refuse {@code admin.01} here is to know its hash in advance. The list is produced offline by
 * {@code policy-username-hashes} (libsignal fork, {@code rust/policy}) from the same lexicon the clients enforce, and
 * shipped as a file next to the server's configuration.
 * <p>
 * What this does and does not promise (ADR-0062 §5.4 as revised by ADR-0066):
 * <ul>
 *   <li>Every {@code <reserved nickname>.<discriminator>} for discriminators {@code 01}–{@code 99} is refused. ADR-0066
 *       fixes the discriminator at {@code 01}, so that is what every stock client sends; {@code 02}–{@code 99} are the
 *       shape upstream's default candidates had and still read like an official account.</li>
 *   <li>Exact: no false positives, no false negatives inside that range.</li>
 *   <li>Three or more digits ({@code tellomi.123}) are not refused. Official clients show any discriminator other than
 *       {@code 01} in full, so such a name does not pass for {@code tellomi}.</li>
 * </ul>
 * File layout, integers little endian:
 * {@code "TLPH" | u32 format (1) | u64 lexicon version | u32 highest discriminator | u32 count
 * | [32] SHA-256 of the body | body: count × 32-byte hashes, strictly ascending as unsigned bytes}.
 */
public class UsernameHashDenylist {

  private static final Logger log = LoggerFactory.getLogger(UsernameHashDenylist.class);

  private static final byte[] MAGIC = {'T', 'L', 'P', 'H'};
  private static final int SUPPORTED_FORMAT = 1;
  private static final int HASH_BYTES = 32;
  private static final int HEADER_BYTES = 4 + 4 + 8 + 4 + 4 + HASH_BYTES;

  private final long lexiconVersion;
  private final int highestDiscriminator;
  /** Sorted by {@link Arrays#compareUnsigned(byte[], byte[])}, the same order Rust gives {@code [u8; 32]}. */
  private final byte[][] hashes;

  private UsernameHashDenylist(final long lexiconVersion, final int highestDiscriminator, final byte[][] hashes) {
    this.lexiconVersion = lexiconVersion;
    this.highestDiscriminator = highestDiscriminator;
    this.hashes = hashes;
  }

  /** An empty denylist: refuses nothing. Used when none is configured, so the server behaves as upstream does. */
  public static UsernameHashDenylist empty() {
    return new UsernameHashDenylist(0, 0, new byte[0][]);
  }

  /** Loads a denylist, making the same checks in the same order as the generator's own {@code decode()}. */
  public static UsernameHashDenylist load(final Path path) throws IOException {
    final byte[] raw = Files.readAllBytes(path);
    if (raw.length < HEADER_BYTES) {
      throw new IOException("username denylist is too short to contain a header: " + path);
    }
    if (!Arrays.equals(Arrays.copyOf(raw, MAGIC.length), MAGIC)) {
      throw new IOException("username denylist has the wrong magic; expected TLPH "
          + "(a TLPB file is the old Bloom-filter format — rebuild with the current policy-username-hashes): " + path);
    }

    final ByteBuffer header = ByteBuffer.wrap(raw, MAGIC.length, HEADER_BYTES - MAGIC.length)
        .order(ByteOrder.LITTLE_ENDIAN);
    final int format = header.getInt();
    if (format != SUPPORTED_FORMAT) {
      throw new IOException("username denylist format " + format + " is not supported (expected " + SUPPORTED_FORMAT
          + "); rebuild it with a matching policy-username-hashes");
    }
    final long lexiconVersion = header.getLong();
    final int highestDiscriminator = header.getInt();
    final long count = Integer.toUnsignedLong(header.getInt());
    final byte[] expectedDigest = new byte[HASH_BYTES];
    header.get(expectedDigest);

    final long bodyBytes = raw.length - (long) HEADER_BYTES;
    if (bodyBytes != count * HASH_BYTES) {
      throw new IOException("username denylist body is " + bodyBytes + " bytes but the header declares " + count
          + " × " + HASH_BYTES);
    }
    final byte[] actualDigest = sha256(raw, HEADER_BYTES, (int) bodyBytes);
    if (!MessageDigest.isEqual(expectedDigest, actualDigest)) {
      throw new IOException("username denylist body does not match the SHA-256 in its header: " + path);
    }

    final byte[][] hashes = new byte[(int) count][];
    for (int i = 0; i < count; i++) {
      final int offset = HEADER_BYTES + i * HASH_BYTES;
      hashes[i] = Arrays.copyOfRange(raw, offset, offset + HASH_BYTES);
      if (i > 0 && Arrays.compareUnsigned(hashes[i - 1], hashes[i]) >= 0) {
        // Binary search below depends on this; the generator sorts and dedups, so this means a corrupt or foreign file.
        throw new IOException("username denylist hashes are not strictly ascending at index " + i + ": " + path);
      }
    }

    log.info("Loaded username denylist: lexicon version {}, {} hashes (discriminators 01–{}), body sha256 {}",
        lexiconVersion, count, highestDiscriminator, HexFormat.of().formatHex(actualDigest));
    return new UsernameHashDenylist(lexiconVersion, highestDiscriminator, hashes);
  }

  public boolean isEmpty() {
    return hashes.length == 0;
  }

  public long lexiconVersion() {
    return lexiconVersion;
  }

  public int highestDiscriminator() {
    return highestDiscriminator;
  }

  public int size() {
    return hashes.length;
  }

  /**
   * @param usernameHash the 32-byte hash a client submits for reservation
   * @return whether this username is reserved
   */
  public boolean contains(final byte[] usernameHash) {
    if (usernameHash == null || usernameHash.length != HASH_BYTES || isEmpty()) {
      return false;
    }
    return Arrays.binarySearch(hashes, usernameHash, Arrays::compareUnsigned) >= 0;
  }

  private static byte[] sha256(final byte[] input, final int offset, final int length) {
    try {
      final MessageDigest digest = MessageDigest.getInstance("SHA-256");
      digest.update(input, offset, length);
      return digest.digest();
    } catch (final NoSuchAlgorithmException e) {
      throw new AssertionError("Every JVM ships SHA-256", e);
    }
  }
}
