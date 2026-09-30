/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.s3;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.MockClock;
import io.micrometer.core.instrument.simple.SimpleConfig;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.slf4j.LoggerFactory;

/// tellomi/tellomi#1399：监控一份本地文件、有变化时通知监听者的 `S3ObjectMonitor` 替身。
///
/// 轮询由测试手动驱动（`poll()`），不依赖睡眠；真实调度器的一条路径在 `RemoteDeprecationFileReloadTest` 里走。
class FileObjectMonitorTest {

  private static final Duration INTERVAL = Duration.ofSeconds(10);
  private static final long MAX_SIZE = 1024;
  private static final String ERROR_METER = "chat.FileObjectMonitor.error";
  private static final String CHANGED_METER = "chat.FileObjectMonitor.changed";

  @TempDir
  Path directory;

  private Path file;
  private ScheduledExecutorService executor;
  private ScheduledFuture<?> scheduledFuture;
  private SimpleMeterRegistry registry;
  private final List<String> received = new ArrayList<>();
  private Consumer<InputStream> listener;
  private ListAppender<ILoggingEvent> logAppender;
  private ch.qos.logback.classic.Logger monitorLogger;

  @BeforeEach
  void setUp() {
    file = directory.resolve("dynamic.yml");

    executor = mock(ScheduledExecutorService.class);
    scheduledFuture = mock(ScheduledFuture.class);
    doReturn(scheduledFuture).when(executor).scheduleAtFixedRate(any(), anyLong(), anyLong(), any());

    registry = new SimpleMeterRegistry();

    listener = inputStream -> {
      try {
        received.add(new String(inputStream.readAllBytes(), StandardCharsets.UTF_8));
      } catch (final IOException e) {
        throw new UncheckedIOException(e);
      }
    };

    monitorLogger = (ch.qos.logback.classic.Logger) LoggerFactory.getLogger(FileObjectMonitor.class);
    monitorLogger.setLevel(Level.DEBUG);
    logAppender = new ListAppender<>();
    logAppender.start();
    monitorLogger.addAppender(logAppender);
  }

  @AfterEach
  void tearDown() {
    monitorLogger.detachAppender(logAppender);
    monitorLogger.setLevel(null);
  }

  private FileObjectMonitor monitor() {
    return new FileObjectMonitor(file, MAX_SIZE, executor, INTERVAL, registry);
  }

  private static String readAll(final InputStream inputStream) {
    try {
      return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
    } catch (final IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  private FileObjectMonitor startedMonitor(final String initialContent) throws IOException {
    write(initialContent);
    final FileObjectMonitor monitor = monitor();
    monitor.start(listener);
    return monitor;
  }

  private void write(final String content) throws IOException {
    Files.writeString(file, content);
  }

  private double errors(final String reason) {
    return registry.find(ERROR_METER).tag("reason", reason).counters().stream().mapToDouble(Counter::count).sum();
  }

  private double changes() {
    return registry.find(CHANGED_METER).counters().stream().mapToDouble(Counter::count).sum();
  }

  // ---- 启动 ----

  @Test
  void startDeliversTheInitialContentSynchronously() throws IOException {
    startedMonitor("a: 1\n");

    assertThat(received).containsExactly("a: 1\n");
  }

  @Test
  void startSchedulesPollingAtTheConfiguredInterval() throws IOException {
    startedMonitor("a: 1\n");

    verify(executor).scheduleAtFixedRate(any(Runnable.class), eq(10_000L), eq(10_000L), eq(TimeUnit.MILLISECONDS));
  }

  /// 首次启动文件不存在 = 直接失败（服务起不来），而不是悄悄用缺省配置：
  /// 静默缺省会让运维以为配置生效了——对「最低版本」这类配置，缺省 = 不拦，恰恰是最危险的误会
  @Test
  void startFailsFastWhenTheFileDoesNotExist() {
    assertThatThrownBy(() -> monitor().start(listener))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining(file.toString())
        .hasMessageContaining("missing");

    assertThat(received).isEmpty();
    verify(executor, never()).scheduleAtFixedRate(any(), anyLong(), anyLong(), any());
  }

  @Test
  void startFailsFastWhenThePathIsADirectory() throws IOException {
    Files.createDirectory(file);

    assertThatThrownBy(() -> monitor().start(listener))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("unreadable");

    assertThat(received).isEmpty();
    verify(executor, never()).scheduleAtFixedRate(any(), anyLong(), anyLong(), any());
  }

  @Test
  void startFailsFastWhenTheFileIsTooLarge() throws IOException {
    write("x".repeat((int) MAX_SIZE + 1));

    assertThatThrownBy(() -> monitor().start(listener))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("too_large");

    assertThat(received).isEmpty();
  }

  @Test
  void aFileExactlyAtTheLimitIsFine() throws IOException {
    startedMonitor("x".repeat((int) MAX_SIZE));

    assertThat(received).hasSize(1);
  }

  @Test
  void startingTwiceIsAnError() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    assertThatThrownBy(() -> monitor.start(listener)).isInstanceOf(IllegalStateException.class);
    assertThat(received).hasSize(1);
  }

  @Test
  void aListenerThatFailsDuringStartFailsTheStart() throws IOException {
    write("a: 1\n");

    assertThatThrownBy(() -> monitor().start(inputStream -> {
      throw new IllegalArgumentException("boom");
    })).isInstanceOf(IllegalArgumentException.class);

    verify(executor, never()).scheduleAtFixedRate(any(), anyLong(), anyLong(), any());
  }

  @Test
  void stopCancelsThePolling() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    monitor.stop();

    verify(scheduledFuture).cancel(true);
  }

  @Test
  void stopBeforeStartIsHarmless() {
    assertThatCode(() -> monitor().stop()).doesNotThrowAnyException();
  }

  @Test
  void theConstructorRejectsNonsense() {
    assertThatThrownBy(() -> new FileObjectMonitor(file, 0, executor, INTERVAL, registry))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("maxSize");
    assertThatThrownBy(() -> new FileObjectMonitor(file, FileObjectMonitor.MAX_ALLOWED_SIZE + 1, executor, INTERVAL,
        registry)).isInstanceOf(IllegalArgumentException.class).hasMessageContaining("maxSize");
    assertThatThrownBy(() -> new FileObjectMonitor(file, MAX_SIZE, executor, Duration.ZERO, registry))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("refreshInterval");
    assertThatThrownBy(() -> new FileObjectMonitor(file, MAX_SIZE, executor, Duration.ofSeconds(-1), registry))
        .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("refreshInterval");
  }

  /// 打开一个没有写端的 FIFO 会一直阻塞——那会把（唯一的）刷新线程永远卡住。特殊文件不打开，当「读不了」
  @Test
  void aFifoIsNeverOpened() throws Exception {
    write("a: 1\n");
    final FileObjectMonitor monitor = monitor();
    monitor.start(listener);

    Files.delete(file);

    final Process mkfifo;
    try {
      mkfifo = new ProcessBuilder("mkfifo", file.toString()).start();
    } catch (final IOException e) {
      assumeTrue(false, "mkfifo is not available on this system");
      return;
    }
    assumeTrue(mkfifo.waitFor() == 0, "mkfifo failed on this system");

    assertTimeoutPreemptively(Duration.ofSeconds(5), monitor::poll);

    assertThat(received).containsExactly("a: 1\n");
    assertThat(errors("unreadable")).isEqualTo(1);
  }

  // ---- 轮询：变化 ----

  @Test
  void anUnchangedFileIsNotDeliveredAgain() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    monitor.poll();
    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n");
    assertThat(changes()).isZero();
  }

  /// 新内容要连续两次轮询都读到同样的字节才交付：编辑器正写到一半时读到半截文件，
  /// 半截的 YAML 很可能恰好合法（比如 `ANDROID: 175101` 被截成 `ANDROID: 17`），不能把它当成新配置
  @Test
  void aChangeIsDeliveredOnlyAfterItHasHeldStillForOnePoll() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    write("a: 2\n");
    monitor.poll();
    assertThat(received).as("first sighting: wait").containsExactly("a: 1\n");

    monitor.poll();
    assertThat(received).as("seen twice in a row: deliver").containsExactly("a: 1\n", "a: 2\n");
    assertThat(changes()).isEqualTo(1);

    monitor.poll();
    assertThat(received).as("and only once").hasSize(2);
  }

  @Test
  void aHalfWrittenFileIsNeverDelivered() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("minimumBuilds: 175101\n");

    // 编辑器把文件截断后写了一半：这一刻被轮询读到
    write("minimumBuilds: 17");
    monitor.poll();

    // 写完了
    write("minimumBuilds: 175200\n");
    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("minimumBuilds: 175101\n", "minimumBuilds: 175200\n");
    assertThat(received).as("the half-written version never reached the listener").doesNotContain("minimumBuilds: 17");
  }

  @Test
  void aFileThatKeepsChangingIsNotDeliveredUntilItStops() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("v: 0\n");

    for (int i = 1; i <= 5; i++) {
      write("v: " + i + "\n");
      monitor.poll();
    }
    assertThat(received).as("still changing on every poll").containsExactly("v: 0\n");

    monitor.poll();
    assertThat(received).containsExactly("v: 0\n", "v: 5\n");
  }

  @Test
  void aChangeThatIsRevertedBeforeItSettlesDeliversNothing() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    write("a: 2\n");
    monitor.poll();
    write("a: 1\n");
    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n");
  }

  @Test
  void aSecondChangeAfterTheFirstIsDeliveredToo() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    write("a: 2\n");
    monitor.poll();
    monitor.poll();
    write("a: 3\n");
    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n", "a: 2\n", "a: 3\n");
  }

  /// 常见的「原子替换」：先写临时文件、再 mv 过去（也是 sed -i / rsync 的做法）
  @Test
  void atomicallyReplacingTheFileWorks() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    final Path replacement = directory.resolve("dynamic.yml.new");
    Files.writeString(replacement, "a: 2\n");
    Files.move(replacement, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);

    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n", "a: 2\n");
  }

  @Test
  void followsASymbolicLink() throws IOException {
    final Path target = directory.resolve("real.yml");
    Files.writeString(target, "a: 1\n");
    Files.createSymbolicLink(file, target);

    final FileObjectMonitor monitor = monitor();
    monitor.start(listener);

    Files.writeString(target, "a: 2\n");
    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n", "a: 2\n");
  }

  @Test
  void anEmptyFileIsJustAnotherVersion() throws IOException {
    // 是否合法交给解析 / 校验那一层（它会拒绝并保留上一份好的）；监控器只管「字节变了」
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    write("");
    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n", "");
  }

  // ---- 轮询：读不到 ----

  /// 文件被删：不交付任何东西（调用方手里仍是上一份好的配置），计数、记一条日志；恢复后照常工作
  @Test
  void aDeletedFileDeliversNothingAndIsCounted() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    Files.delete(file);
    monitor.poll();
    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n");
    assertThat(errors("missing")).isEqualTo(3);

    // 原样恢复：内容没变，不必再交付
    write("a: 1\n");
    monitor.poll();
    assertThat(received).containsExactly("a: 1\n");
    assertThat(errors("missing")).isEqualTo(3);

    // 换成新内容：照常（要稳定两次）
    write("a: 2\n");
    monitor.poll();
    monitor.poll();
    assertThat(received).containsExactly("a: 1\n", "a: 2\n");
  }

  @Test
  void aFailedReadResetsAChangeThatWasWaitingToSettle() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    write("a: 2\n");
    monitor.poll(); // 第一次看到 a: 2
    Files.delete(file);
    monitor.poll(); // 读不到
    write("a: 2\n");
    monitor.poll(); // 重新算第一次
    assertThat(received).as("the failure in between means it has not held still").containsExactly("a: 1\n");

    monitor.poll();
    assertThat(received).containsExactly("a: 1\n", "a: 2\n");
  }

  @Test
  void aFileThatGrowsTooLargeIsRejectedAndCounted() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    write("x".repeat((int) MAX_SIZE + 1));
    monitor.poll();
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n");
    assertThat(errors("too_large")).isEqualTo(2);

    // 改回正常大小
    write("a: 3\n");
    monitor.poll();
    monitor.poll();
    assertThat(received).containsExactly("a: 1\n", "a: 3\n");
  }

  @Test
  void aFileReplacedByADirectoryIsCountedAsUnreadable() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    Files.delete(file);
    Files.createDirectory(file);
    monitor.poll();

    assertThat(received).containsExactly("a: 1\n");
    assertThat(errors("unreadable")).isEqualTo(1);
  }

  // ---- 轮询：监听者出问题 ----

  /// 监听者拒绝一版内容（比如 YAML 的根是 `~`：上游的解析对它抛 `IllegalArgumentException`，而不是计数）：
  /// 记一条 WARN、计一次，调用方继续用上一份好的；**同一版内容不再重复交付**——重试不会变好，只会每个间隔刷一条带栈的 WARN
  @Test
  void aVersionTheListenerRefusesIsOfferedOnlyOnce() throws IOException {
    write("a: 1\n");
    final List<String> offered = new ArrayList<>();
    final FileObjectMonitor monitor = monitor();
    monitor.start(refusingTheNullDocument(offered));

    write("~\n");
    for (int i = 0; i < 6; i++) {
      monitor.poll();
    }

    assertThat(offered).as("the refused version is offered exactly once").containsExactly("a: 1\n", "~\n");
    assertThat(errors("listener")).isEqualTo(1);
    assertThat(changes()).as("nothing was delivered").isZero();
    assertThat(logAppender.list.stream().filter(event -> event.getLevel() == Level.WARN)).hasSize(1);

    // 内容再变了（改对了），照常交付
    write("a: 2\n");
    monitor.poll();
    monitor.poll();
    assertThat(offered).containsExactly("a: 1\n", "~\n", "a: 2\n");
    assertThat(changes()).isEqualTo(1);
  }

  /// 「拒绝过」的记忆只管这一版：换成别的内容（交付成功）之后，同一版内容再出现，照样交付一次（也许这回监听者不拒绝了）
  @Test
  void aRefusedVersionIsOfferedAgainWhenItComesBackAfterADifferentOne() throws IOException {
    write("a: 1\n");
    final List<String> offered = new ArrayList<>();
    final FileObjectMonitor monitor = monitor();
    monitor.start(refusingTheNullDocument(offered));

    write("~\n");
    monitor.poll();
    monitor.poll();
    write("a: 2\n");
    monitor.poll();
    monitor.poll();
    write("~\n");
    monitor.poll();
    monitor.poll();

    assertThat(offered).containsExactly("a: 1\n", "~\n", "a: 2\n", "~\n");
    assertThat(errors("listener")).isEqualTo(2);
  }

  @Test
  void goingBackToTheLastGoodVersionForgetsTheRefusal() throws IOException {
    write("a: 1\n");
    final List<String> offered = new ArrayList<>();
    final FileObjectMonitor monitor = monitor();
    monitor.start(refusingTheNullDocument(offered));

    write("~\n");
    monitor.poll();
    monitor.poll();
    write("a: 1\n");
    monitor.poll();
    write("~\n");
    monitor.poll();
    monitor.poll();

    assertThat(offered).containsExactly("a: 1\n", "~\n", "~\n");
    assertThat(errors("listener")).isEqualTo(2);
  }

  private static Consumer<InputStream> refusingTheNullDocument(final List<String> offered) {
    return inputStream -> {
      final String content = readAll(inputStream);
      offered.add(content);

      if (content.startsWith("~")) {
        throw new IllegalArgumentException("HV000116: The object to be validated must not be null.");
      }
    };
  }

  /// 周期任务一旦抛出任何东西，`scheduleAtFixedRate` 就再也不会执行它——配置从此悄悄冻住。所以任何东西都不能从任务里抛出来
  @Test
  void theScheduledTaskSurvivesAnythingItsListenerThrows() throws IOException {
    write("a: 1\n");
    final List<String> offered = new ArrayList<>();
    final boolean[] explode = {false};
    final FileObjectMonitor monitor = monitor();
    monitor.start(inputStream -> {
      offered.add(readAll(inputStream));

      if (explode[0]) {
        throw new StackOverflowError("a pathological file");
      }
    });

    final ArgumentCaptor<Runnable> task = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).scheduleAtFixedRate(task.capture(), anyLong(), anyLong(), any());

    explode[0] = true;
    write("a: 2\n");
    assertThatCode(() -> {
      task.getValue().run();
      task.getValue().run();
    }).doesNotThrowAnyException();
    assertThat(errors("internal")).as("an Error is not a RuntimeException").isEqualTo(1);

    // 拒绝过的这一版不再交付；下一版不同的内容照常交付（任务还活着）
    explode[0] = false;
    task.getValue().run();
    task.getValue().run();
    assertThat(offered).containsExactly("a: 1\n", "a: 2\n");

    write("a: 3\n");
    task.getValue().run();
    task.getValue().run();
    assertThat(offered).containsExactly("a: 1\n", "a: 2\n", "a: 3\n");
  }

  /// 出错的可能正是指标注册表本身：连「记一笔 internal」也不能让任何东西逃出周期任务
  @Test
  void theScheduledTaskSurvivesABrokenMeterRegistry() throws IOException {
    final MeterRegistry brokenRegistry = new SimpleMeterRegistry() {
      @Override
      public Counter counter(final String name, final String... tags) {
        throw new AssertionError("the registry is broken");
      }
    };

    write("a: 1\n");
    final FileObjectMonitor monitor = new FileObjectMonitor(file, MAX_SIZE, executor, INTERVAL, brokenRegistry);
    monitor.start(listener);

    final ArgumentCaptor<Runnable> task = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).scheduleAtFixedRate(task.capture(), anyLong(), anyLong(), any());

    Files.delete(file);

    assertThatCode(() -> task.getValue().run()).doesNotThrowAnyException();
  }

  // ---- stop() 打断正在读的那一轮 ----

  /// `stop()` 用 `cancel(true)` 打断刷新线程：正在读的那一轮不算读失败，什么都不记，中断标志还回去
  @Test
  void aPollInterruptedByStopIsNotAFailure() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    Thread.currentThread().interrupt();
    try {
      monitor.poll();
      assertThat(Thread.currentThread().isInterrupted()).as("the interrupt flag is handed back").isTrue();
    } finally {
      Thread.interrupted(); // 清掉，别影响别的用例
    }

    assertThat(errors("unreadable")).isZero();
    assertThat(logAppender.list.stream().filter(event -> event.getLevel() == Level.WARN)).isEmpty();
    assertThat(received).containsExactly("a: 1\n");
  }

  // ---- 存活指标 ----

  /// 事件计数器只在出事时才动：轮询线程卡死、文件读不了、执行器没了，看起来和「文件没变」一模一样。
  /// 这个 gauge 只在**成功读到文件**时往前走，停住就是信号
  @Test
  void theLastSuccessfulReadGaugeOnlyMovesWhenTheFileWasRead() throws IOException {
    final MockClock clock = new MockClock();
    final MeterRegistry clockedRegistry = new SimpleMeterRegistry(SimpleConfig.DEFAULT, clock);
    clock.addSeconds(1_000);

    write("a: 1\n");
    final FileObjectMonitor monitor = new FileObjectMonitor(file, MAX_SIZE, executor, INTERVAL, clockedRegistry);
    monitor.start(listener);
    assertThat(lastSuccessfulRead(clockedRegistry)).isEqualTo(1_000);

    clock.addSeconds(10);
    monitor.poll();
    assertThat(lastSuccessfulRead(clockedRegistry)).isEqualTo(1_010);

    Files.delete(file);
    clock.addSeconds(10);
    monitor.poll();
    clock.addSeconds(10);
    monitor.poll();
    assertThat(lastSuccessfulRead(clockedRegistry)).as("stale while the file cannot be read").isEqualTo(1_010);

    write("a: 1\n");
    clock.addSeconds(10);
    monitor.poll();
    assertThat(lastSuccessfulRead(clockedRegistry)).as("the file is readable again").isEqualTo(1_040);
  }

  private double lastSuccessfulRead(final MeterRegistry meterRegistry) {
    return meterRegistry.get("chat.FileObjectMonitor.lastSuccessfulReadEpochSeconds")
        .tag("path", file.toString()).gauge().value();
  }

  // ---- 日志 ----

  @Test
  void logsSizeAndAShortHashOfAChangeButNeverTheContent() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("remoteDeprecation: {}\n");

    write("captcha: {scoreFloor: 0.5}\nsome-secret-looking-token: abcdef\n");
    monitor.poll();
    monitor.poll();

    assertThat(logAppender.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .anySatisfy(message -> assertThat(message).contains(file.toString()).contains("sha256="));
    assertThat(logAppender.list)
        .extracting(ILoggingEvent::getFormattedMessage)
        .noneMatch(message -> message.contains("some-secret-looking-token") || message.contains("scoreFloor")
            || message.contains("remoteDeprecation"));
  }

  @Test
  void aReadFailureIsLoggedAsAWarningOnlyWhenItStartsNotOnEveryPoll() throws IOException {
    final FileObjectMonitor monitor = startedMonitor("a: 1\n");

    Files.delete(file);
    for (int i = 0; i < 5; i++) {
      monitor.poll();
    }

    assertThat(logAppender.list.stream().filter(event -> event.getLevel() == Level.WARN)).hasSize(1);

    write("a: 1\n");
    monitor.poll();

    assertThat(logAppender.list.stream().filter(event -> event.getLevel() == Level.INFO))
        .extracting(ILoggingEvent::getFormattedMessage)
        .anySatisfy(message -> assertThat(message).contains("readable again"));
  }
}
