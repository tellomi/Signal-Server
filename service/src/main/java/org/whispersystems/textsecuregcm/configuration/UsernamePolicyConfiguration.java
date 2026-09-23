/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.validation.constraints.NotBlank;

/**
 * Tellomi: where to find the username denylist produced by {@code policy-username-hashes} (ADR-0062 §5.4).
 * <p>
 * Optional. With no {@code usernamePolicy} block the server behaves exactly as upstream and reserves whatever a client
 * asks for; that is the right default for the local stack and for tests.
 *
 * @param denylistPath path to the {@code username-denylist-<version>.bloom} file
 * @param required     whether a missing or malformed file should stop the server from starting. Production sets this
 *                     true so that a bad deploy fails loudly instead of quietly accepting {@code admin.01}.
 */
public record UsernamePolicyConfiguration(@NotBlank String denylistPath, boolean required) {
}
