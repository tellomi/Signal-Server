/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.captcha;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.micrometer.core.instrument.Metrics;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.TurnstileCaptchaConfiguration;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

/**
 * Tellomi: a {@link CaptchaClient} backed by Cloudflare Turnstile. Upstream keeps its real captcha clients in the
 * private spam-filter plugin and ships only {@link CaptchaClient#noop()}; this is the one we run in production.
 * <p>
 * Token scheme (as delivered by clients): {@code turnstile.<siteKey>.<action>.<token>}. Turnstile has no risk score, so
 * a successful siteverify is reported as score 1.0 and a failed one as {@link AssessmentResult#invalid()}.
 *
 * @see <a href="https://developers.cloudflare.com/turnstile/get-started/server-side-validation/">siteverify</a>
 */
public class TurnstileCaptchaClient implements CaptchaClient {

  public static final String SCHEME = "turnstile";

  private static final Logger logger = LoggerFactory.getLogger(TurnstileCaptchaClient.class);
  private static final String VERIFY_COUNTER = name(TurnstileCaptchaClient.class, "verify");

  private final TurnstileCaptchaConfiguration configuration;
  private final HttpClient httpClient;
  private final Set<String> siteKeys;

  public TurnstileCaptchaClient(final TurnstileCaptchaConfiguration configuration) {
    this(configuration, HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build());
  }

  TurnstileCaptchaClient(final TurnstileCaptchaConfiguration configuration, final HttpClient httpClient) {
    this.configuration = configuration;
    this.httpClient = httpClient;
    // CaptchaChecker lower-cases the site key it parses out of the token before asking validSiteKeys()
    this.siteKeys = Set.of(configuration.siteKey().toLowerCase(Locale.ROOT).strip());
  }

  @Override
  public String scheme() {
    return SCHEME;
  }

  @Override
  public Set<String> validSiteKeys(final Action action) {
    return siteKeys;
  }

  @Override
  public AssessmentResult verify(final Optional<UUID> maybeAci, final String siteKey, final Action action,
      final String token, final String ip, @Nullable final String userAgent) throws IOException {

    final StringBuilder form = new StringBuilder()
        .append("secret=").append(encode(configuration.secret().value()))
        .append("&response=").append(encode(token));
    if (ip != null && !ip.isBlank()) {
      form.append("&remoteip=").append(encode(ip));
    }

    final HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(configuration.verifyUrl()))
        .timeout(Duration.ofSeconds(10))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .POST(HttpRequest.BodyPublishers.ofString(form.toString()))
        .build();

    final HttpResponse<String> response;
    try {
      response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    } catch (final InterruptedException e) {
      Thread.currentThread().interrupt();
      throw new IOException(e);
    }

    if (response.statusCode() != 200) {
      Metrics.counter(VERIFY_COUNTER, "outcome", "http-" + response.statusCode()).increment();
      throw new IOException("Turnstile siteverify HTTP " + response.statusCode());
    }

    final SiteVerifyResponse result = SystemMapper.jsonMapper().readValue(response.body(), SiteVerifyResponse.class);

    // Turnstile echoes the widget's `action`; if the page set one it must match what the client claimed
    final boolean actionMatches = result.action() == null || result.action().isBlank()
        || result.action().equalsIgnoreCase(action.getActionName());

    if (result.success() && actionMatches) {
      Metrics.counter(VERIFY_COUNTER, "outcome", "success").increment();
      return AssessmentResult.fromScore(1.0f, 0.0f);
    }

    logger.info("Turnstile rejected token: success={} action={} errors={}", result.success(), result.action(),
        result.errorCodes());
    Metrics.counter(VERIFY_COUNTER, "outcome", result.success() ? "action-mismatch" : "rejected").increment();
    return AssessmentResult.invalid();
  }

  private static String encode(final String value) {
    return URLEncoder.encode(value, StandardCharsets.UTF_8);
  }

  @JsonIgnoreProperties(ignoreUnknown = true)
  record SiteVerifyResponse(@JsonProperty("success") boolean success,
                            @JsonProperty("action") @Nullable String action,
                            @JsonProperty("hostname") @Nullable String hostname,
                            @JsonProperty("error-codes") @Nullable List<String> errorCodes) {
  }
}
