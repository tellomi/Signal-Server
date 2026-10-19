/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.attachments;
import java.util.Map;

public interface AttachmentGenerator {

  record Descriptor(Map<String, String> headers, String signedUploadLocation) {}

  Descriptor generateAttachment(final String key, final long uploadLength);

  /**
   * Tellomi (REGION_PROFILE §6.2): same as {@link #generateAttachment(String, long)}, with the upload URL moved to the
   * Tellomi root ({@code tellomi.app} / {@code tellomi.cn}) the client connected through. Generators whose URL is not
   * a Tellomi host (GCS) return it unchanged.
   */
  default Descriptor generateAttachment(final String key, final long uploadLength,
      @javax.annotation.Nullable final String forwardedHost, @javax.annotation.Nullable final String host) {
    final Descriptor d = generateAttachment(key, uploadLength);
    return new Descriptor(d.headers(), TellomiRegionalHost.rehost(d.signedUploadLocation(), forwardedHost, host));
  }

}
