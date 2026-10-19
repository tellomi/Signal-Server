/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.attachments;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Locale;
import javax.annotation.Nullable;

/**
 * Tellomi (REGION_PROFILE §6.2): the same server answers on {@code *.tellomi.app} (global) and {@code *.tellomi.cn}
 * (cn). An upload URL handed to a client has to stay inside the region the client connected through, or a cn client
 * would be sent back to {@code upload.tellomi.app} (Desktop uses {@code signedUploadLocation} as-is).
 *
 * <p>Only the registrable root is swapped and only between the two known roots; the label ({@code upload.}), scheme,
 * port, path and query are untouched. Anything else (unknown request host, a URL outside both roots) is returned
 * unchanged, so a spoofed Host header can at worst pick the other Tellomi root.
 */
public final class TellomiRegionalHost {

  static final List<String> ROOTS = List.of("tellomi.app", "tellomi.cn");

  private TellomiRegionalHost() {
  }

  /** Root ({@code tellomi.app} / {@code tellomi.cn}) of a Host header value, or null. Port and trailing dot ignored. */
  @Nullable
  static String rootOf(@Nullable final String hostHeader) {
    if (hostHeader == null) {
      return null;
    }
    String host = hostHeader.trim().toLowerCase(Locale.ROOT);
    final int comma = host.indexOf(',');
    if (comma >= 0) {
      host = host.substring(0, comma).trim();   // X-Forwarded-Host may be a list; the first is the client-facing one
    }
    if (host.startsWith("[")) {
      return null;
    }
    final int colon = host.indexOf(':');
    if (colon >= 0) {
      host = host.substring(0, colon);
    }
    if (host.endsWith(".")) {
      host = host.substring(0, host.length() - 1);
    }
    for (final String root : ROOTS) {
      if (host.equals(root) || host.endsWith("." + root)) {
        return root;
      }
    }
    return null;
  }

  /**
   * @param uri the configured URL (e.g. {@code https://upload.tellomi.app})
   * @param forwardedHost {@code X-Forwarded-Host}, preferred when it names a Tellomi root
   * @param host {@code Host} (over the WebSocket this is the upgrade request's Host)
   */
  public static String rehost(final String uri, @Nullable final String forwardedHost, @Nullable final String host) {
    String requestRoot = rootOf(forwardedHost);
    if (requestRoot == null) {
      requestRoot = rootOf(host);
    }
    if (requestRoot == null || uri == null) {
      return uri;
    }
    try {
      final URI parsed = new URI(uri);
      final String uriHost = parsed.getHost();
      if (uriHost == null) {
        return uri;
      }
      final String uriRoot = rootOf(uriHost);
      if (uriRoot == null || uriRoot.equals(requestRoot)) {
        return uri;
      }
      final String lower = uriHost.toLowerCase(Locale.ROOT);
      final String newHost = lower.substring(0, lower.length() - uriRoot.length()) + requestRoot;
      return new URI(parsed.getScheme(), parsed.getUserInfo(), newHost, parsed.getPort(), parsed.getPath(),
          parsed.getQuery(), parsed.getFragment()).toString();
    } catch (final URISyntaxException e) {
      return uri;
    }
  }
}
