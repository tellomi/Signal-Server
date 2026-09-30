/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.s3;

import java.net.URI;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.configuration.CdnConfiguration;
import org.whispersystems.textsecuregcm.configuration.PagedSingleUseKEMPreKeyStoreConfiguration;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3AsyncClient;

/**
 * Builds the S3 clients for the cdn (avatar) bucket and the KEM pre-key page bucket. The main service and the
 * command-line tools both go through here so that they always talk to the same endpoint: with an S3-compatible store
 * such as Cloudflare R2 ({@code region: auto} plus {@code endpointOverride}), a client built without the override
 * would silently talk to AWS instead.
 */
public final class S3AsyncClients {

  private S3AsyncClients() {
  }

  public static S3AsyncClient forCdn(final CdnConfiguration configuration) {
    return build(configuration.credentials().build(), configuration.region(), configuration.endpointOverride());
  }

  public static S3AsyncClient forKemPreKeyPages(final PagedSingleUseKEMPreKeyStoreConfiguration configuration,
      final AwsCredentialsProvider credentialsProvider) {

    return build(credentialsProvider, configuration.region(), configuration.endpointOverride());
  }

  private static S3AsyncClient build(final AwsCredentialsProvider credentialsProvider,
      final String region,
      @Nullable final URI endpointOverride) {

    return S3AsyncClient.builder()
        .credentialsProvider(credentialsProvider)
        .region(Region.of(region))
        .endpointOverride(endpointOverride)
        .build();
  }
}
