/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.attachments;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class TellomiRegionalHostTest {

  @ParameterizedTest
  @CsvSource(nullValues = "null", value = {
      // uri, forwardedHost, host, expected
      "https://upload.tellomi.app, null, chat.tellomi.cn, https://upload.tellomi.cn",
      "https://upload.tellomi.app, null, grpc.chat.tellomi.cn:443, https://upload.tellomi.cn",
      "https://upload.tellomi.app, null, CHAT.TELLOMI.CN., https://upload.tellomi.cn",
      "https://upload.tellomi.app/attachments, null, chat.tellomi.cn, https://upload.tellomi.cn/attachments",
      "https://upload.tellomi.app:8443/x?y=1, null, chat.tellomi.cn, https://upload.tellomi.cn:8443/x?y=1",
      "https://upload.tellomi.cn, null, chat.tellomi.app, https://upload.tellomi.app",
      "https://upload.tellomi.app, null, chat.tellomi.app, https://upload.tellomi.app",
      // X-Forwarded-Host wins when it names a Tellomi root; a list uses its first entry
      "https://upload.tellomi.app, 'chat.tellomi.cn, proxy.internal', localhost:8080, https://upload.tellomi.cn",
      "https://upload.tellomi.app, chat.tellomi.cn, chat.tellomi.app, https://upload.tellomi.cn",
      "https://upload.tellomi.app, evil.example, chat.tellomi.cn, https://upload.tellomi.cn",
      // unknown request host / no host / foreign upload URL: unchanged
      "https://upload.tellomi.app, null, localhost:8080, https://upload.tellomi.app",
      "https://upload.tellomi.app, null, null, https://upload.tellomi.app",
      "https://upload.tellomi.app, null, nottellomi.cn, https://upload.tellomi.app",
      "https://upload.tellomi.app, null, '[::1]:443', https://upload.tellomi.app",
      "https://storage.googleapis.com/b, null, chat.tellomi.cn, https://storage.googleapis.com/b",
      "https://xtellomi.app/a, null, chat.tellomi.cn, https://xtellomi.app/a",
  })
  void rehost(final String uri, final String forwardedHost, final String host, final String expected) {
    assertThat(TellomiRegionalHost.rehost(uri, forwardedHost, host)).isEqualTo(expected);
  }

  @Test
  void generatorDefaultMethodRehostsTheUploadLocation() {
    final AttachmentGenerator generator = (key, length) ->
        new AttachmentGenerator.Descriptor(Map.of("h", "v"), "https://upload.tellomi.app/attachments");
    final AttachmentGenerator.Descriptor d = generator.generateAttachment("k", 1, null, "chat.tellomi.cn");
    assertThat(d.signedUploadLocation()).isEqualTo("https://upload.tellomi.cn/attachments");
    assertThat(d.headers()).containsEntry("h", "v");
  }
}
