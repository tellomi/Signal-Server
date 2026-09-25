/*
 * Copyright 2023 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.securevaluerecovery;

import static org.whispersystems.textsecuregcm.util.HeaderUtils.basicAuthHeader;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.net.HttpHeaders;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.auth.ExternalServiceCredentials;
import org.whispersystems.textsecuregcm.auth.ExternalServiceCredentialsGenerator;
import org.whispersystems.textsecuregcm.configuration.SecureValueRecoveryConfiguration;
import org.whispersystems.textsecuregcm.http.FaultTolerantHttpClient;
import org.whispersystems.textsecuregcm.util.HttpUtils;

/**
 * A client for sending requests to Signal's secure value recovery service on behalf of authenticated users.
 */
public class SecureValueRecoveryClient {

  private static final Logger logger = LoggerFactory.getLogger(SecureValueRecoveryClient.class);

  private final ExternalServiceCredentialsGenerator secureValueRecoveryCredentialsGenerator;
  private final URI deleteUri;
  private final Supplier<List<Integer>> allowedDeletionErrorStatusCodes;
  private final FaultTolerantHttpClient httpClient;

  // Tellomi (tellomi/tellomi#1237): no SVR enclave is deployed, and the deployed config keeps upstream's placeholder
  // uri (svr2.example.com, no scheme). With it every removeData() threw IllegalArgumentException *synchronously*,
  // inside the allOf(...) of AccountsManager.delete() and after the storage-service delete had already gone out, so
  // deleting an account always failed and left it half deleted. A uri that is not an absolute http(s) URL now means
  // "not deployed": removeData() completes at once and sends nothing.
  private final boolean deployed;

  @VisibleForTesting
  static final String DELETE_PATH = "/v1/delete";

  public SecureValueRecoveryClient(
      final ExternalServiceCredentialsGenerator secureValueRecoveryCredentialsGenerator,
      final Executor executor, final ScheduledExecutorService retryExecutor,
      final SecureValueRecoveryConfiguration configuration,
      Supplier<List<Integer>> allowedDeletionErrorStatusCodes)
      throws CertificateException {
    this.secureValueRecoveryCredentialsGenerator = secureValueRecoveryCredentialsGenerator;
    final URI baseUri = URI.create(configuration.uri());
    this.deployed = isHttpUrl(baseUri);
    if (!deployed) {
      logger.warn("Tellomi: secure value recovery uri {} is not an absolute http(s) URL; treating it as not deployed, "
          + "so removeData() will not contact it", configuration.uri());
    }
    this.deleteUri = baseUri.resolve(DELETE_PATH);
    this.allowedDeletionErrorStatusCodes = allowedDeletionErrorStatusCodes;
    this.httpClient = FaultTolerantHttpClient.newBuilder("secure-value-recovery", executor)
        .withCircuitBreaker(configuration.circuitBreakerConfigurationName())
        .withRetry(configuration.retryConfigurationName(), retryExecutor)
        .withVersion(HttpClient.Version.HTTP_1_1)
        .withConnectTimeout(Duration.ofSeconds(10))
        .withRedirect(HttpClient.Redirect.NEVER)
        .withSecurityProtocol(FaultTolerantHttpClient.SECURITY_PROTOCOL_TLS_1_2)
        .withTrustedServerCertificates(configuration.svrCaCertificates().toArray(new String[0]))
        .build();
  }

  public CompletableFuture<Void> removeData(final UUID accountUuid) {
    return removeData(accountUuid.toString());
  }

  public CompletableFuture<Void> removeData(final String userIdentifier) {

    if (!deployed) {
      // Tellomi (#1237): nothing was ever stored in an SVR that does not exist, so there is nothing to remove.
      return CompletableFuture.completedFuture(null);
    }

    final ExternalServiceCredentials credentials = secureValueRecoveryCredentialsGenerator.generateFor(userIdentifier);

    final HttpRequest request = HttpRequest.newBuilder()
        .uri(deleteUri)
        .DELETE()
        .header(HttpHeaders.AUTHORIZATION, basicAuthHeader(credentials))
        .build();

    return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString()).thenApply(response -> {
      if (HttpUtils.isSuccessfulResponse(response.statusCode())) {
        return null;
      }

      final List<Integer> allowedErrors = allowedDeletionErrorStatusCodes.get();
      if (allowedErrors.contains(response.statusCode())) {
        logger.warn("Ignoring failure to delete svr entry for identifier {} with status {}",
            userIdentifier, response.statusCode());
        return null;
      }
      logger.warn("Failed to delete svr entry for identifier {} with status {}", userIdentifier, response.statusCode());
      throw new SecureValueRecoveryException("Failed to delete backup", String.valueOf(response.statusCode()));
    });
  }

  @VisibleForTesting
  boolean isDeployed() {
    return deployed;
  }

  private static boolean isHttpUrl(final URI uri) {
    return uri.isAbsolute()
        && ("https".equalsIgnoreCase(uri.getScheme()) || "http".equalsIgnoreCase(uri.getScheme()))
        && uri.getHost() != null;
  }
}
