/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.util.logging;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.matches;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.net.HttpHeaders;
import jakarta.inject.Provider;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.Response;
import java.lang.reflect.Field;
import java.util.List;
import org.glassfish.jersey.server.ContainerRequest;
import org.glassfish.jersey.server.ExtendedUriInfo;
import org.glassfish.jersey.uri.UriTemplate;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

/// tellomi/tellomi#1682: a request without a User-Agent must not turn a 5xx into a bare 500. Before the fix the mapper
/// threw a NullPointerException while formatting its log line, and Jersey answered with a 500 that had lost the
/// original status and headers (for example the Retry-After of a 503).
class LoggingUnhandledExceptionMapperMissingUserAgentTest {

  @Test
  void aRequestWithoutUserAgentKeepsTheStatusAndHeadersOfA5xx() throws Exception {
    final Logger logger = mock(Logger.class);
    final LoggingUnhandledExceptionMapper mapper = new LoggingUnhandledExceptionMapper(logger);

    final ContainerRequest request = mock(ContainerRequest.class);
    final ExtendedUriInfo uriInfo = mock(ExtendedUriInfo.class);
    when(request.getMethod()).thenReturn("GET");
    when(request.getUriInfo()).thenReturn(uriInfo);
    when(uriInfo.getMatchedTemplates()).thenReturn(List.of(new UriTemplate("/v1/test")));
    when(request.getHeaderString(HttpHeaders.USER_AGENT)).thenReturn(null);

    // the HTTP test client always sends a User-Agent (HttpURLConnection fills one in), so inject the request directly
    final Field field = LoggingUnhandledExceptionMapper.class.getDeclaredField("request");
    field.setAccessible(true);
    final Provider<ContainerRequest> provider = () -> request;
    field.set(mapper, provider);

    final Response unavailable = Response.status(503).header("Retry-After", "30").build();
    final Response response = mapper.toResponse(new WebApplicationException(unavailable));

    assertEquals(503, response.getStatus());
    assertEquals("30", response.getHeaderString("Retry-After"));
    verify(logger).error(matches(".* at GET /v1/test \\(missing\\)"), any(Throwable.class));
  }
}
