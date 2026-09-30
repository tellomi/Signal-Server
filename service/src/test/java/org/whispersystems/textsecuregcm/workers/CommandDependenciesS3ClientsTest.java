/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.workers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.whispersystems.textsecuregcm.WhisperServerConfiguration;
import org.whispersystems.textsecuregcm.configuration.CdnConfiguration;
import org.whispersystems.textsecuregcm.configuration.PagedSingleUseKEMPreKeyStoreConfiguration;
import org.whispersystems.textsecuregcm.configuration.StaticAwsCredentialsFactory;
import org.whispersystems.textsecuregcm.configuration.secrets.SecretString;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.services.s3.S3AsyncClient;

/**
 * The command-line tools (remove-expired-accounts, delete-user, remove-orphaned-pre-key-pages) delete avatars and KEM
 * pre-key pages through the S3 clients built here. Tellomi keeps both buckets on Cloudflare R2 ({@code region: auto}
 * plus {@code endpointOverride}), so a client that ignores {@code endpointOverride} talks to AWS and fails.
 */
class CommandDependenciesS3ClientsTest {

  private static final String REGION = "auto";

  private static final AwsCredentialsProvider CREDENTIALS_PROVIDER =
      StaticCredentialsProvider.create(AwsBasicCredentials.create("access-key-id", "secret-access-key"));

  private HttpServer fakeObjectStore;
  private final List<String> requests = new CopyOnWriteArrayList<>();

  @BeforeEach
  void setUp() throws IOException {
    // A stand-in for R2: records "<method> <path>" for every request and answers 204 No Content
    fakeObjectStore = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
    fakeObjectStore.createContext("/", exchange -> {
      requests.add(exchange.getRequestMethod() + " " + exchange.getRequestURI().getPath());
      exchange.sendResponseHeaders(204, -1);
      exchange.close();
    });
    fakeObjectStore.start();
  }

  @AfterEach
  void tearDown() {
    fakeObjectStore.stop(0);
  }

  private URI fakeObjectStoreEndpoint() {
    return URI.create("http://127.0.0.1:" + fakeObjectStore.getAddress().getPort());
  }

  @Test
  void cdnClientUsesConfiguredEndpointOverride() {
    final WhisperServerConfiguration configuration = mock(WhisperServerConfiguration.class);
    when(configuration.getCdnConfiguration()).thenReturn(new CdnConfiguration(
        new StaticAwsCredentialsFactory(new SecretString("access-key-id"), new SecretString("secret-access-key")),
        "cdn-bucket", REGION, fakeObjectStoreEndpoint()));

    try (final S3AsyncClient client = CommandDependencies.buildCdnS3Client(configuration)) {
      assertThat(client.serviceClientConfiguration().endpointOverride()).contains(fakeObjectStoreEndpoint());
      client.deleteObject(request -> request.bucket("cdn-bucket").key("profiles/avatar")).join();
    }

    assertThat(requests).containsExactly("DELETE /cdn-bucket/profiles/avatar");
  }

  @Test
  void kemPreKeyPageClientUsesConfiguredEndpointOverride() {
    final WhisperServerConfiguration configuration = mock(WhisperServerConfiguration.class);
    when(configuration.getPagedSingleUseKEMPreKeyStore()).thenReturn(
        new PagedSingleUseKEMPreKeyStoreConfiguration("kem-bucket", REGION, fakeObjectStoreEndpoint()));

    try (final S3AsyncClient client =
        CommandDependencies.buildKemPreKeyPageS3Client(configuration, CREDENTIALS_PROVIDER)) {

      assertThat(client.serviceClientConfiguration().endpointOverride()).contains(fakeObjectStoreEndpoint());
      client.deleteObject(request -> request.bucket("kem-bucket").key("page")).join();
    }

    assertThat(requests).containsExactly("DELETE /kem-bucket/page");
  }

  @Test
  void clientsFallBackToTheDefaultEndpointWithoutOverride() {
    // AWS deployments leave endpointOverride out of the configuration
    final WhisperServerConfiguration configuration = mock(WhisperServerConfiguration.class);
    when(configuration.getCdnConfiguration()).thenReturn(new CdnConfiguration(
        new StaticAwsCredentialsFactory(new SecretString("access-key-id"), new SecretString("secret-access-key")),
        "cdn-bucket", "us-west-2", null));
    when(configuration.getPagedSingleUseKEMPreKeyStore()).thenReturn(
        new PagedSingleUseKEMPreKeyStoreConfiguration("kem-bucket", "us-west-2", null));

    try (final S3AsyncClient cdnClient = CommandDependencies.buildCdnS3Client(configuration);
        final S3AsyncClient kemClient =
            CommandDependencies.buildKemPreKeyPageS3Client(configuration, CREDENTIALS_PROVIDER)) {

      assertThat(cdnClient.serviceClientConfiguration().endpointOverride()).isEmpty();
      assertThat(kemClient.serviceClientConfiguration().endpointOverride()).isEmpty();
    }
  }
}
