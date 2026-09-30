/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.ValueInstantiationException;
import io.dropwizard.configuration.ConfigurationParsingException;
import io.dropwizard.configuration.ConfigurationValidationException;
import io.dropwizard.configuration.FileConfigurationSourceProvider;
import io.dropwizard.configuration.YamlConfigurationFactory;
import io.dropwizard.jackson.Jackson;
import jakarta.validation.Valid;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.constraints.NotNull;
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

  // ---- 走 Dropwizard 自己的配置工厂：服务端读静态配置（含 dynamicConfig）的真实路径 ----

  /// `WhisperServerConfiguration.dynamicConfig` 的声明方式
  public static class Holder {

    @Valid
    @NotNull
    @JsonProperty
    private S3ObjectMonitorFactory dynamicConfig;
  }

  private static Holder dropwizardParse(final Path directory, final String yaml) throws Exception {
    final ObjectMapper mapper = Jackson.newObjectMapper();
    // 和 WhisperServerService.initialize 一样：先套上 SystemMapper 的配置（它关了 FAIL_ON_UNKNOWN_PROPERTIES）
    SystemMapper.configureMapper(mapper);

    final Path configFile = directory.resolve("server.yml");
    Files.writeString(configFile, yaml);

    return new YamlConfigurationFactory<>(Holder.class, VALIDATOR, mapper, "dw")
        .build(new FileConfigurationSourceProvider(), configFile.toString());
  }

  /// 注意：服务端真实的 `WhisperServerConfiguration` 对未知键是严格的（写错的字段启动前就被拒绝，见 PR 里 `CheckServiceConfigurations` 的实跑），
  /// 这里的 `Holder` 只有一个字段、没有这层严格性，所以「写错字段被拒」不在这些单测里断言——只测 `type: file` 块自己的解析和校验
  @Test
  void dropwizardParsesTypeFile(@TempDir final Path directory) throws Exception {
    final Holder holder = dropwizardParse(directory, "dynamicConfig:\n  type: file\n  path: /x/dynamic.yml\n");

    assertThat(holder.dynamicConfig).isInstanceOf(FileObjectMonitorFactory.class);
    assertThat(((FileObjectMonitorFactory) holder.dynamicConfig).path()).isEqualTo("/x/dynamic.yml");
  }

  @Test
  void dropwizardStillParsesTheS3BlockWithoutAType(@TempDir final Path directory) throws Exception {
    final Holder holder = dropwizardParse(directory, """
        dynamicConfig:
          s3Region: a-region
          s3Bucket: a-bucket
          objectKey: dynamic-config.yaml
        """);

    assertThat(holder.dynamicConfig).isInstanceOf(MonitoredS3ObjectConfiguration.class);
  }

  @Test
  void dropwizardRejectsAMissingPath(@TempDir final Path directory) {
    assertThatThrownBy(() -> dropwizardParse(directory, "dynamicConfig:\n  type: file\n  refreshInterval: PT10S\n"))
        .isInstanceOf(ConfigurationValidationException.class)
        .hasMessageContaining("dynamicConfig.path");
  }

  @Test
  void dropwizardRejectsAnIntervalBelowOneSecond(@TempDir final Path directory) {
    assertThatThrownBy(() -> dropwizardParse(directory,
        "dynamicConfig:\n  type: file\n  path: /x\n  refreshInterval: PT0S\n"))
        .isInstanceOf(ConfigurationParsingException.class)
        .hasMessageContaining("refreshInterval");
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
