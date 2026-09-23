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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tellomi: reserved / brand / impersonation usernames, as a Bloom filter over their hashes.
 * <p>
 * The server never sees a username in the clear — clients reserve {@code Username::hash()} and that is all we store —
 * so the only way to refuse {@code admin.01} here is to know its hash in advance. The filter is produced offline by
 * {@code policy-username-hashes} (libsignal fork, {@code rust/policy}) from the same lexicon the clients enforce, and
 * shipped as a file next to the server's configuration.
 * <p>
 * What this does and does not promise (ADR-0062 §5.4):
 * <ul>
 *   <li>No false negatives for the enumerated space: every {@code <reserved nickname>.<discriminator>} a stock client
 *       would offer is in the filter.</li>
 *   <li>Rare false positives (~1e-6) are harmless: the client is already iterating over a list of candidates and moves
 *       on to the next one.</li>
 *   <li>A modified client can pick a discriminator outside the enumerated ranges. Catching that is the client-side
 *       engine's job; the server's copy is a backstop, not the whole defence.</li>
 * </ul>
 */
public class UsernameHashDenylist {

  private static final Logger log = LoggerFactory.getLogger(UsernameHashDenylist.class);

  /** Header: "TLPB" | u32 format | u64 lexicon version | u64 bits | u32 hash count, all little endian. */
  private static final byte[] MAGIC = {'T', 'L', 'P', 'B'};
  private static final int SUPPORTED_FORMAT = 1;
  private static final int HEADER_BYTES = 4 + 4 + 8 + 8 + 4;

  private final long lexiconVersion;
  private final long bits;
  private final int hashCount;
  private final byte[] data;

  private UsernameHashDenylist(final long lexiconVersion, final long bits, final int hashCount, final byte[] data) {
    this.lexiconVersion = lexiconVersion;
    this.bits = bits;
    this.hashCount = hashCount;
    this.data = data;
  }

  /** An empty denylist: refuses nothing. Used when no filter is configured, so the server behaves as upstream does. */
  public static UsernameHashDenylist empty() {
    return new UsernameHashDenylist(0, 0, 0, new byte[0]);
  }

  public static UsernameHashDenylist load(final Path path) throws IOException {
    final byte[] raw = Files.readAllBytes(path);
    if (raw.length < HEADER_BYTES) {
      throw new IOException("username denylist is too short to contain a header: " + path);
    }
    if (!Arrays.equals(Arrays.copyOf(raw, MAGIC.length), MAGIC)) {
      throw new IOException("username denylist has the wrong magic; expected TLPB: " + path);
    }

    final ByteBuffer header = ByteBuffer.wrap(raw, MAGIC.length, HEADER_BYTES - MAGIC.length)
        .order(ByteOrder.LITTLE_ENDIAN);
    final int format = header.getInt();
    if (format != SUPPORTED_FORMAT) {
      throw new IOException("username denylist format " + format + " is not supported (expected " + SUPPORTED_FORMAT
          + "); rebuild it with a matching policy-username-hashes");
    }
    final long lexiconVersion = header.getLong();
    final long bits = header.getLong();
    final int hashCount = header.getInt();

    if (bits <= 0 || hashCount <= 0) {
      throw new IOException("username denylist header is not sane: bits=" + bits + " hashes=" + hashCount);
    }
    final long expectedBytes = (bits + 7) / 8;
    final long actualBytes = raw.length - (long) HEADER_BYTES;
    if (actualBytes != expectedBytes) {
      throw new IOException("username denylist is truncated: header declares " + expectedBytes + " bytes of bitmap, "
          + "file has " + actualBytes);
    }

    final byte[] data = Arrays.copyOfRange(raw, HEADER_BYTES, raw.length);
    log.info("Loaded username denylist: lexicon version {}, {} bits, {} hash functions, {} KiB",
        lexiconVersion, bits, hashCount, data.length / 1024);
    return new UsernameHashDenylist(lexiconVersion, bits, hashCount, data);
  }

  public boolean isEmpty() {
    return bits == 0;
  }

  public long lexiconVersion() {
    return lexiconVersion;
  }

  /**
   * @param usernameHash the 32-byte hash a client submits for reservation
   * @return whether this username is reserved (with the filter's small false-positive probability)
   */
  public boolean contains(final byte[] usernameHash) {
    if (isEmpty() || usernameHash == null) {
      return false;
    }

    // Kirsch-Mitzenmacher: one SHA-256 of the username hash supplies both base hashes, mirroring the generator.
    final byte[] digest = sha256(usernameHash);
    final ByteBuffer buffer = ByteBuffer.wrap(digest).order(ByteOrder.LITTLE_ENDIAN);
    final long h1 = buffer.getLong();
    final long h2 = buffer.getLong() | 1L;

    for (int i = 0; i < hashCount; i++) {
      final long position = Long.remainderUnsigned(h1 + h2 * i, bits);
      final int index = (int) (position / 8);
      if ((data[index] & (1 << (position % 8))) == 0) {
        return false;
      }
    }
    return true;
  }

  private static byte[] sha256(final byte[] input) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(input);
    } catch (final NoSuchAlgorithmException e) {
      throw new AssertionError("Every JVM ships SHA-256", e);
    }
  }
}
