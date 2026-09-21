/*
 * Copyright 2026 Tellomi
 * SPDX-License-Identifier: AGPL-3.0-only
 */
package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import io.dropwizard.core.setup.Environment;
import io.grpc.CallCredentials;
import io.grpc.Metadata;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import java.io.IOException;
import java.util.concurrent.Executor;
import java.util.concurrent.ScheduledExecutorService;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretBytes;
import org.whispersystems.textsecuregcm.registration.RegistrationServiceClient;

/**
 * Tellomi: a self-hosted registration-service reached over TLS on a private network, without GCP workload-identity
 * tokens (the upstream {@link RegistrationServiceConfiguration} requires an external-account credential JSON).
 * Authentication is the network boundary (loopback / private VPC) plus TLS; add a shared-secret interceptor on both
 * sides before exposing it beyond that.
 */
@JsonTypeName("plain")
public record PlainRegistrationServiceConfiguration(@NotBlank String host,
                                                    int port,
                                                    @NotBlank String registrationCaCertificate,
                                                    @NotNull SecretBytes collationKeySalt) implements
    RegistrationServiceClientFactory {

  @Override
  public RegistrationServiceClient build(final Environment environment,
      final ScheduledExecutorService identityRefreshExecutor) {
    try {
      return new RegistrationServiceClient(host, port, NO_CALL_CREDENTIALS, registrationCaCertificate,
          collationKeySalt.value());
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  private static final CallCredentials NO_CALL_CREDENTIALS = new CallCredentials() {
    @Override
    public void applyRequestMetadata(final RequestInfo requestInfo, final Executor appExecutor,
        final MetadataApplier applier) {
      applier.apply(new Metadata());
    }
  };
}
