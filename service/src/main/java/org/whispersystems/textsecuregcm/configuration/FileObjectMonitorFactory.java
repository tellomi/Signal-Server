/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import jakarta.validation.constraints.NotBlank;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.ScheduledExecutorService;
import javax.annotation.Nullable;
import org.whispersystems.textsecuregcm.s3.FileObjectMonitor;
import org.whispersystems.textsecuregcm.s3.S3ObjectMonitor;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;

/// `dynamicConfig` 的第三种来源（另两种：S3 监控 = 不写 `type`，`type: static` = 内联，仅测试 / 本地栈用）：一份**本地文件**，
/// 定期重读，改了不必重启服务。tellomi/tellomi#1399；行为见 `FileObjectMonitor`。
///
/// ```yaml
/// dynamicConfig:
///   type: file
///   path: /opt/signal/config/dynamic.yml   # 必填；建议绝对路径
///   refreshInterval: PT10S                 # 可选，缺省 10 秒，至少 1 秒
///   maxSize: 1048576                       # 可选，字节，缺省 1 MiB，最大 16 MiB
/// ```
///
/// 可选：不写 `type: file` = 上游行为，一个字节都不变。文件里的内容和 S3 上那份动态配置完全一样（`DynamicConfiguration` 的 YAML），
/// 同样经过解析和 Bean Validation；改坏了（语法错、校验不过、被删）就保留上一份好的，并计数、记日志。
///
/// 「改完 ≤ 60 秒生效」：新内容要连续两次轮询读到同样的字节才生效，最坏 = 两个 `refreshInterval`（缺省 20 秒）加一次解析。
///
/// @param path            文件路径
/// @param maxSize         文件大小上限（字节）；超过 = 读失败（保留上一份好的）。缺省 1 MiB
/// @param refreshInterval 轮询间隔。缺省 10 秒，至少 1 秒
@JsonTypeName("file")
public record FileObjectMonitorFactory(
    @NotBlank String path,
    @Nullable Long maxSize,
    @Nullable Duration refreshInterval) implements S3ObjectMonitorFactory {

  public static final long DEFAULT_MAX_SIZE = 1024 * 1024;
  public static final Duration DEFAULT_REFRESH_INTERVAL = Duration.ofSeconds(10);
  public static final Duration MINIMUM_REFRESH_INTERVAL = Duration.ofSeconds(1);

  public FileObjectMonitorFactory {
    if (maxSize == null) {
      maxSize = DEFAULT_MAX_SIZE;
    }

    if (refreshInterval == null) {
      refreshInterval = DEFAULT_REFRESH_INTERVAL;
    }

    if (maxSize < 1 || maxSize > FileObjectMonitor.MAX_ALLOWED_SIZE) {
      throw new IllegalArgumentException(
          "maxSize must be between 1 and %d bytes: %d".formatted(FileObjectMonitor.MAX_ALLOWED_SIZE, maxSize));
    }

    if (refreshInterval.compareTo(MINIMUM_REFRESH_INTERVAL) < 0) {
      throw new IllegalArgumentException(
          "refreshInterval must be at least %s: %s".formatted(MINIMUM_REFRESH_INTERVAL, refreshInterval));
    }
  }

  @Override
  public S3ObjectMonitor build(final AwsCredentialsProvider awsCredentialsProvider,
      final ScheduledExecutorService refreshExecutorService) {

    // 不碰 S3：用不到 AWS 凭证
    return new FileObjectMonitor(Path.of(path), maxSize, refreshExecutorService, refreshInterval);
  }
}
