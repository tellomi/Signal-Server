/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.s3;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import com.google.common.annotations.VisibleForTesting;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.attribute.BasicFileAttributes;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import javax.annotation.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/// 监控一份**本地文件**、内容变了就通知监听者：`S3ObjectMonitor` 的替身，接口相同（`start(listener)` / `stop()`），
/// 所以上游的 `DynamicConfigurationManager` 原样可用——它负责解析、Bean Validation、「新配置不合法就保留上一份好的」并计数。
/// 静态配置里写 `dynamicConfig: {type: file, path: …}` 即可启用（见 `FileObjectMonitorFactory`）；不写 = 上游行为。
///
/// 这个类**不碰 S3**：不建 S3 客户端、不需要 AWS 凭证。它只继承 `S3ObjectMonitor` 的类型（`DynamicConfigurationManager` 要它），
/// 不使用继承来的任何状态，所以父类那个只给测试用的构造方法里的 `S3Client` 传 `null`（所以本类才放在同一个包里）。
///
/// ## 行为
///
/// - **首次读取在 `start()` 里同步做**。文件不存在 / 读不了 / 太大 = `start()` 抛出 `IllegalStateException`，服务起不来
///   （fail-fast）。理由：静默退回缺省配置，会让运维以为他们写的配置生效了；对「最低版本」这类配置，缺省 = 不拦，恰恰是最危险的误会。
///   （文件在、但内容不合法：由 `DynamicConfigurationManager.start()` 一直等到出现一份合法配置，同样不会悄悄用缺省。）
/// - 之后每个 `refreshInterval` 读一次**全文件**，和上一次交付的字节比较（不看修改时间：原子替换、原地编辑、符号链接都一样工作）。
/// - **新内容要连续两次轮询读到同样的字节才交付**：编辑器把文件截断后写到一半时，读到的半截 YAML 很可能恰好合法
///   （`ANDROID: 175101` 被截成 `ANDROID: 17`），不能当成新配置。所以最坏延迟 = 两个轮询间隔。
/// - 读不到（被删、被换成目录、权限不对、超过 `maxSize`）：**什么都不交付**，调用方继续用上一份好的配置；计数
///   `error{reason=missing|unreadable|too_large}`，失败开始时记一条 WARN（持续失败不刷屏），恢复时记一条 INFO。
///   读失败会清掉「等着稳定」的那份新内容（中间断过 = 不算稳定）。
/// - 监听者抛异常：计数 `error{reason=listener}`，这一版内容下一次轮询重新交付。任何东西都不会从周期任务里抛出来
///   （抛出来 = `scheduleAtFixedRate` 再也不执行它 = 配置从此悄悄冻住）。
/// - 日志只写路径、字节数和 SHA-256 的前 12 位十六进制，**从不写内容**；运维可以拿 `sha256sum 文件` 对照，确认服务读到的就是这一版。
public class FileObjectMonitor extends S3ObjectMonitor {

  private static final Logger log = LoggerFactory.getLogger(FileObjectMonitor.class);

  /// 文件大小上限的上限（保证 `maxSize + 1` 放得进 int）
  public static final long MAX_ALLOWED_SIZE = 16L * 1024 * 1024;

  private static final String ERROR_METER_NAME = name(FileObjectMonitor.class, "error");
  private static final String CHANGED_METER_NAME = name(FileObjectMonitor.class, "changed");
  private static final String REASON_TAG_NAME = "reason";

  static final String MISSING = "missing";
  static final String UNREADABLE = "unreadable";
  static final String TOO_LARGE = "too_large";
  static final String LISTENER = "listener";
  static final String INTERNAL = "internal";

  private final Path path;
  private final long maxSize;
  private final ScheduledExecutorService refreshExecutorService;
  private final Duration refreshInterval;
  private final MeterRegistry meterRegistry;

  private ScheduledFuture<?> refreshFuture;

  // 下面这些状态只由 start()（调度之前）和之后的刷新线程访问：scheduleAtFixedRate 保证同一个任务不会并发执行
  private Consumer<InputStream> changeListener;
  @Nullable
  private byte[] delivered;
  @Nullable
  private byte[] pending;
  @Nullable
  private String ongoingFailure;

  public FileObjectMonitor(final Path path, final long maxSize, final ScheduledExecutorService refreshExecutorService,
      final Duration refreshInterval) {

    this(path, maxSize, refreshExecutorService, refreshInterval, Metrics.globalRegistry);
  }

  @VisibleForTesting
  FileObjectMonitor(final Path path, final long maxSize, final ScheduledExecutorService refreshExecutorService,
      final Duration refreshInterval, final MeterRegistry meterRegistry) {

    super(null, "file", path.toString(), maxSize, refreshExecutorService, refreshInterval);

    if (maxSize < 1 || maxSize > MAX_ALLOWED_SIZE) {
      throw new IllegalArgumentException("maxSize must be between 1 and " + MAX_ALLOWED_SIZE + " bytes: " + maxSize);
    }

    if (refreshInterval.isZero() || refreshInterval.isNegative()) {
      throw new IllegalArgumentException("refreshInterval must be positive: " + refreshInterval);
    }

    this.path = path;
    this.maxSize = maxSize;
    this.refreshExecutorService = refreshExecutorService;
    this.refreshInterval = refreshInterval;
    this.meterRegistry = meterRegistry;
  }

  @Override
  public synchronized void start(final Consumer<InputStream> changeListener) {
    if (this.changeListener != null) {
      throw new IllegalStateException("File object monitor already started");
    }

    final byte[] initialContent;

    try {
      initialContent = read();
    } catch (final ReadFailure e) {
      // fail-fast，见类注释
      throw new IllegalStateException(
          "Cannot read the configuration file %s (%s): %s".formatted(path, e.reason, e.getMessage()), e);
    }

    log.info("Watching {} every {}; initial content is {}", path, refreshInterval, describe(initialContent));

    // 监听者在这里抛异常 = 启动失败；先交付，成功了才算启动
    deliver(changeListener, initialContent);
    this.changeListener = changeListener;

    refreshFuture = refreshExecutorService.scheduleAtFixedRate(this::tick, refreshInterval.toMillis(),
        refreshInterval.toMillis(), TimeUnit.MILLISECONDS);
  }

  @Override
  public synchronized void stop() {
    if (refreshFuture != null) {
      refreshFuture.cancel(true);
    }
  }

  /// 调度器每个间隔调用一次。任何东西都不会从这里抛出去
  private void tick() {
    try {
      poll();
    } catch (final Throwable t) {
      // 包括 Error（比如病态文件让解析栈溢出）：周期任务一旦抛出，就再也不会被调度了
      log.error("Unexpected error while checking {}", path, t);
      error(INTERNAL);
    }
  }

  /// 读一次文件、该交付就交付。单独成方法，测试可以不靠调度器手动驱动
  @VisibleForTesting
  void poll() {
    final byte[] current;

    try {
      current = read();
    } catch (final ReadFailure e) {
      pending = null;
      recordFailure(e);
      return;
    }

    if (ongoingFailure != null) {
      log.info("{} is readable again", path);
      ongoingFailure = null;
    }

    if (Arrays.equals(current, delivered)) {
      // 没变；或者变了又改回去了
      pending = null;
      return;
    }

    if (!Arrays.equals(current, pending)) {
      // 第一次看到这一版（或者还在变）：等它在下一次轮询时仍然一样
      pending = current;
      log.debug("{} changed ({}); waiting for it to hold still for one more poll", path, describe(current));
      return;
    }

    try {
      deliver(changeListener, current);
      pending = null;
    } catch (final RuntimeException e) {
      // 留着 pending：下一次轮询重新交付
      log.warn("Listener failed to process the new content of {} ({}); will retry", path, describe(current), e);
      error(LISTENER);
    }
  }

  private void deliver(final Consumer<InputStream> listener, final byte[] content) {
    listener.accept(new ByteArrayInputStream(content));

    final boolean initialDelivery = delivered == null;
    delivered = content;

    if (!initialDelivery) {
      log.info("{} changed; delivered the new content ({})", path, describe(content));
      meterRegistry.counter(CHANGED_METER_NAME).increment();
    }
  }

  private byte[] read() throws ReadFailure {
    try {
      // 先看是不是普通文件（跟随符号链接）：目录、FIFO、设备文件不去打开——打开一个没有写端的 FIFO 会把刷新线程永远卡住
      if (!Files.readAttributes(path, BasicFileAttributes.class).isRegularFile()) {
        throw new ReadFailure(UNREADABLE, "not a regular file", null);
      }

      final byte[] content;

      try (final InputStream inputStream = Files.newInputStream(path)) {
        content = inputStream.readNBytes((int) maxSize + 1);
      }

      if (content.length > maxSize) {
        throw new ReadFailure(TOO_LARGE, "the file is larger than " + maxSize + " bytes", null);
      }

      return content;
    } catch (final NoSuchFileException e) {
      throw new ReadFailure(MISSING, "the file does not exist", e);
    } catch (final IOException e) {
      throw new ReadFailure(UNREADABLE, e.getClass().getSimpleName() + ": " + e.getMessage(), e);
    }
  }

  private void recordFailure(final ReadFailure failure) {
    error(failure.reason);

    // 失败开始（或原因变了）时记一条 WARN；持续失败不刷屏
    if (!failure.reason.equals(ongoingFailure)) {
      log.warn("Cannot read {} ({}): {}; keeping the last good content", path, failure.reason, failure.getMessage());
      ongoingFailure = failure.reason;
    } else {
      log.debug("Still cannot read {} ({})", path, failure.reason);
    }
  }

  private void error(final String reason) {
    meterRegistry.counter(ERROR_METER_NAME, REASON_TAG_NAME, reason).increment();
  }

  /// 「N bytes, sha256=…」：够运维核对「服务读到的是哪一版」，又不泄露内容
  private static String describe(final byte[] content) {
    try {
      final byte[] digest = MessageDigest.getInstance("SHA-256").digest(content);
      return "%d bytes, sha256=%s".formatted(content.length, HexFormat.of().formatHex(digest, 0, 6));
    } catch (final NoSuchAlgorithmException e) {
      // 每个 JVM 都必须支持 SHA-256
      throw new AssertionError(e);
    }
  }

  private static class ReadFailure extends Exception {

    private final String reason;

    ReadFailure(final String reason, final String message, @Nullable final Throwable cause) {
      super(message, cause);
      this.reason = reason;
    }
  }
}
