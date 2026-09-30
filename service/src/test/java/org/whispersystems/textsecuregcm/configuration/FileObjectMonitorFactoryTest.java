/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.exc.ValueInstantiationException;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mockito;
import org.whispersystems.textsecuregcm.s3.FileObjectMonitor;
import org.whispersystems.textsecuregcm.s3.S3ObjectMonitor;
import org.whispersystems.textsecuregcm.util.SystemMapper;

/// tellomi/tellomi#1399：`dynamicConfig: type: file` 的配置块。可选；不写 `type` 的老配置照旧是 S3。
class FileObjectMonitorFactoryTest {

  private static final Validator VALIDATOR = Validation.buildDefaultValidatorFactory().getValidator();

  private static S3ObjectMonitorFactory parse(final String yaml) throws Exception {
    return SystemMapper.yamlMapper().readValue(yaml, S3ObjectMonitorFactory.class);
  }

  @Test
  void onlyThePathIsRequired() throws Exception {
    final S3ObjectMonitorFactory factory = parse("""
        type: file
        path: /opt/signal/config/dynamic.yml
        """);

    assertThat(factory).isInstanceOf(FileObjectMonitorFactory.class);

    final FileObjectMonitorFactory fileFactory = (FileObjectMonitorFactory) factory;
    assertThat(fileFactory.path()).isEqualTo("/opt/signal/config/dynamic.yml");
    assertThat(fileFactory.refreshInterval()).isEqualTo(Duration.ofSeconds(10));
    assertThat(fileFactory.maxSize()).isEqualTo(1024L * 1024);
    assertThat(VALIDATOR.validate(fileFactory)).isEmpty();
  }

  /// 「改完 ≤ 60 秒生效」：新内容要连续两次轮询读到才交付，最坏 = 两个轮询间隔（加一次解析），缺省间隔要让它远小于 60 秒
  @Test
  void theDefaultIntervalKeepsTheWorstCaseWellInsideSixtySeconds() throws Exception {
    final FileObjectMonitorFactory factory = (FileObjectMonitorFactory) parse("type: file\npath: /x\n");

    assertThat(factory.refreshInterval().multipliedBy(2)).isLessThanOrEqualTo(Duration.ofSeconds(30));
  }

  @Test
  void everythingCanBeConfigured() throws Exception {
    final FileObjectMonitorFactory factory = (FileObjectMonitorFactory) parse("""
        type: file
        path: dynamic.yml
        refreshInterval: PT30S
        maxSize: 2048
        """);

    assertThat(factory.path()).isEqualTo("dynamic.yml");
    assertThat(factory.refreshInterval()).isEqualTo(Duration.ofSeconds(30));
    assertThat(factory.maxSize()).isEqualTo(2048L);
  }

  @Test
  void noTypeStillMeansS3() throws Exception {
    // 缺省行为不变：不写 type 的 dynamicConfig 块（sample.yml 的样子）仍然解析成 S3 监控
    final S3ObjectMonitorFactory factory = parse("""
        s3Region: a-region
        s3Bucket: a-bucket
        objectKey: dynamic-config.yaml
        maxSize: 100000
        refreshInterval: PT10S
        """);

    assertThat(factory).isInstanceOf(MonitoredS3ObjectConfiguration.class);
    assertThat(factory).isNotInstanceOf(FileObjectMonitorFactory.class);
  }

  @Test
  void staticStillWorks() throws Exception {
    // 测试 / 本地栈用的 static 类型（test.yml）不受影响
    assertThat(parse("type: static\nobject: |\n  captcha:\n    scoreFloor: 1.0\n"))
        .isInstanceOf(StaticS3ObjectMonitorFactory.class);
  }

  @Test
  void theMissingPathIsAValidationError() throws Exception {
    final S3ObjectMonitorFactory factory = parse("type: file\nrefreshInterval: PT10S\n");

    assertThat(VALIDATOR.validate(factory))
        .extracting(violation -> violation.getPropertyPath().toString())
        .containsExactly("path");
  }

  @Test
  void aBlankPathIsAValidationError() throws Exception {
    final S3ObjectMonitorFactory factory = parse("type: file\npath: \"  \"\n");

    assertThat(VALIDATOR.validate(factory)).isNotEmpty();
  }

  @ParameterizedTest
  @ValueSource(strings = {"PT0S", "PT0.5S", "-PT10S"})
  void anIntervalBelowOneSecondIsRejected(final String interval) {
    assertThatThrownBy(() -> parse("type: file\npath: /x\nrefreshInterval: " + interval + "\n"))
        .isInstanceOf(ValueInstantiationException.class)
        .hasMessageContaining("refreshInterval");
  }

  @ParameterizedTest
  @ValueSource(strings = {"0", "-1", "16777217", "99999999999"})
  void aMaxSizeOutOfRangeIsRejected(final String maxSize) {
    assertThatThrownBy(() -> parse("type: file\npath: /x\nmaxSize: " + maxSize + "\n"))
        .isInstanceOf(ValueInstantiationException.class)
        .hasMessageContaining("maxSize");
  }

  @Test
  void theUpperBoundsAreAccepted() throws Exception {
    final FileObjectMonitorFactory factory =
        (FileObjectMonitorFactory) parse("type: file\npath: /x\nmaxSize: 16777216\nrefreshInterval: PT1S\n");

    assertThat(factory.maxSize()).isEqualTo(16L * 1024 * 1024);
    assertThat(factory.refreshInterval()).isEqualTo(Duration.ofSeconds(1));
  }

  @Test
  void buildsAFileMonitorWithoutTouchingS3(@TempDir final Path directory) throws Exception {
    final Path file = directory.resolve("dynamic.yml");
    Files.writeString(file, "captcha:\n  scoreFloor: 1.0\n");

    final FileObjectMonitorFactory factory =
        (FileObjectMonitorFactory) parse("type: file\npath: " + file + "\n");

    // 不需要 AWS 凭证、不建 S3 客户端
    final S3ObjectMonitor monitor = factory.build(null, Mockito.mock(ScheduledExecutorService.class));

    assertThat(monitor).isInstanceOf(FileObjectMonitor.class);
  }
}
