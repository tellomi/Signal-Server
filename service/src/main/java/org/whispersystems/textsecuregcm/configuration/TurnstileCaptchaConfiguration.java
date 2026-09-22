/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/**
 * Tellomi: Cloudflare Turnstile as the registration / rate-limit-challenge captcha (upstream ships only a no-op client
 * outside its private spam-filter plugin).
 *
 * @param siteKey   the Turnstile site key; clients send it back inside the {@code turnstile.<siteKey>.<action>.<token>}
 *                  captcha string and it must match
 * @param secret    the Turnstile secret key used for siteverify
 * @param verifyUrl the siteverify endpoint
 * @param allowNoop whether the plain {@code noop.noop.<action>.noop} scheme is still accepted (local stack / tests);
 *                  production sets it false
 * @param noopSecret when {@code allowNoop} is false, a {@code noop.noop.<action>.<noopSecret>} token is still accepted —
 *                   this keeps our own tooling (scripted primaries, probes) working while bots cannot guess it; null
 *                   means the noop scheme is rejected outright
 */
public record TurnstileCaptchaConfiguration(@NotBlank String siteKey,
                                            @NotNull SecretString secret,
                                            @NotBlank String verifyUrl,
                                            boolean allowNoop,
                                            @Nullable SecretString noopSecret) {

  public TurnstileCaptchaConfiguration {
    if (verifyUrl == null || verifyUrl.isBlank()) {
      verifyUrl = "https://challenges.cloudflare.com/turnstile/v0/siteverify";
    }
  }
}
