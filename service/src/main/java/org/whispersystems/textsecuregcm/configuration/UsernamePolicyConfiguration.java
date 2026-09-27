/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import java.time.Duration;
import org.whispersystems.textsecuregcm.storage.AccountsManager;

/**
 * Tellomi: username rules that are ours rather than upstream's (ADR-0062 §5.4, ADR-0066).
 * <p>
 * Optional. With no {@code usernamePolicy} block the server reserves whatever a client asks for (upstream behaviour),
 * which is the right default for the local stack and for tests; the rename cooldown still applies, at its default.
 *
 * @param denylistPath   path to the {@code username-hash-denylist-<version>.bin} file produced by
 *                       {@code policy-username-hashes}
 * @param required       whether a missing or malformed denylist should stop the server from starting. Production sets
 *                       this true so that a bad deploy fails loudly instead of quietly accepting {@code admin.01}.
 * @param renameCooldown how long after changing its username an account must wait before changing it again
 *                       (ISO-8601, e.g. {@code P180D}); absent = {@link AccountsManager#DEFAULT_USERNAME_CHANGE_COOLDOWN}.
 *                       This is not the old-name hold, which stays 30 days (Accounts#USERNAME_HOLD_DURATION).
 */
public record UsernamePolicyConfiguration(@NotBlank String denylistPath,
                                          boolean required,
                                          @Nullable Duration renameCooldown) {

  public UsernamePolicyConfiguration {
    if (renameCooldown == null) {
      renameCooldown = AccountsManager.DEFAULT_USERNAME_CHANGE_COOLDOWN;
    }
    if (renameCooldown.isNegative()) {
      throw new IllegalArgumentException("usernamePolicy.renameCooldown must not be negative");
    }
  }

  /// The rename cooldown for a server whose `usernamePolicy` block is `config` (null when there is none).
  public static Duration renameCooldown(@Nullable final UsernamePolicyConfiguration config) {
    return config == null ? AccountsManager.DEFAULT_USERNAME_CHANGE_COOLDOWN : config.renameCooldown();
  }
}
