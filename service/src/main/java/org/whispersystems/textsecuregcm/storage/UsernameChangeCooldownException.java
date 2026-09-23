/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.storage;

import java.time.Duration;

/**
 * Tellomi (ADR-0066, TR-ID-01): the account changed its username less than
 * {@link AccountsManager#USERNAME_CHANGE_COOLDOWN} ago and is asking for a name it does not hold.
 * <p>
 * A subclass of {@link UsernameHashNotAvailableException} so that every existing caller keeps compiling and, at worst,
 * answers "not available". The two public entry points (REST and gRPC) catch it first and answer 429 with
 * {@code Retry-After} instead, so a client can say how long is left rather than "that name is taken".
 */
public class UsernameChangeCooldownException extends UsernameHashNotAvailableException {

  private final Duration retryAfter;

  public UsernameChangeCooldownException(final Duration retryAfter) {
    this.retryAfter = retryAfter;
  }

  public Duration getRetryAfter() {
    return retryAfter;
  }
}
