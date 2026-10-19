/*
 * Copyright 2013 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;

/**
 * @param credentials service account JSON
 * @param proxy       optional (Tellomi): HTTPS forward proxy (CONNECT) used only by the FCM client, for both the
 *                    OAuth token exchange and message sends. Absent (default) = connect to Google directly.
 */
public record FcmConfiguration(@NotNull SecretString credentials, @Nullable @Valid Proxy proxy) {

  public FcmConfiguration(final SecretString credentials) {
    this(credentials, null);
  }

  public record Proxy(@NotNull String host, int port) {
  }
}
