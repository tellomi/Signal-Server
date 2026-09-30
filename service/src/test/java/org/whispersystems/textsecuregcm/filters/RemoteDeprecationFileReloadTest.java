/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.filters;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.timeout;
import static org.mockito.Mockito.verify;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.function.BooleanSupplier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.ArgumentCaptor;
import org.whispersystems.textsecuregcm.auth.AccountAuthenticator;
import org.whispersystems.textsecuregcm.configuration.dynamic.DynamicConfiguration;
import org.whispersystems.textsecuregcm.s3.FileObjectMonitor;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.DynamicConfigurationManager;
import org.whispersystems.textsecuregcm.util.ua.UserAgentUtil;

/// tellomi/tellomi#1399：从「运维改一份本地文件」到「`RemoteDeprecationFilter` 的判定变了」的整条路，
/// 用真实的 `DynamicConfigurationManager`（解析 + Bean Validation + 保留上一份好的）、真实的 `FileObjectMonitor`、
/// 真实的 `RemoteDeprecationFilter`；轮询由测试手动驱动（抓住交给调度器的那个任务，自己 run），除了最后一个用真调度器的用例。
class RemoteDeprecationFileReloadTest {

  private static final String ANDROID = "Signal-Android/0.1.2 Android/34 Build/175101";

  private static final String NO_RULES = """
      captcha:
        scoreFloor: 1.0
      """;

  private static final String MINIMUM_175200 = NO_RULES + """
      remoteDeprecation:
        minimumBuilds:
          ANDROID: 175200
      """;

  private static final String MINIMUM_175000 = NO_RULES + """
      remoteDeprecation:
        minimumBuilds:
          ANDROID: 175000
      """;

  @TempDir
  Path directory;

  private Path file;
  private SimpleMeterRegistry registry;
  private ScheduledExecutorService executor;
  private DynamicConfigurationManager<DynamicConfiguration> manager;
  private RemoteDeprecationFilter filter;
  private Runnable scheduledTask;

  @BeforeEach
  void setUp() {
    registry = new SimpleMeterRegistry();
    Metrics.addRegistry(registry);

    file = directory.resolve("dynamic.yml");

    executor = mock(ScheduledExecutorService.class);
    doReturn(mock(ScheduledFuture.class)).when(executor).scheduleAtFixedRate(any(), anyLong(), anyLong(), any());
  }

  @AfterEach
  void tearDown() {
    Metrics.removeRegistry(registry);
  }

  private void write(final String yaml) throws IOException {
    Files.writeString(file, yaml);
  }

  private void startWith(final ScheduledExecutorService scheduler, final Duration interval) {
    manager = new DynamicConfigurationManager<>(
        new FileObjectMonitor(file, 1024 * 1024, scheduler, interval), DynamicConfiguration.class);
    manager.start();
    filter = new RemoteDeprecationFilter(mock(AccountsManager.class), mock(AccountAuthenticator.class), manager);
  }

  private void start(final String initialYaml) throws IOException {
    write(initialYaml);
    // DynamicConfigurationManager.start() 会一直等到拿到一份合法配置，而且吞掉中断（上游的写法，所以用 assertTimeoutPreemptively）：
    // 实现出错时要让这个测试失败，不能把整个构建挂死
    assertTimeoutPreemptively(Duration.ofSeconds(10), () -> startWith(executor, Duration.ofSeconds(10)));

    final ArgumentCaptor<Runnable> task = ArgumentCaptor.forClass(Runnable.class);
    verify(executor).scheduleAtFixedRate(task.capture(), anyLong(), anyLong(), any());
    scheduledTask = task.getValue();
  }

  /// 调度器每个间隔执行一次这个任务
  private void pollTimes(final int times) {
    for (int i = 0; i < times; i++) {
      scheduledTask.run();
    }
  }

  private boolean blocks(final String userAgent) {
    return filter.shouldBlock(UserAgentUtil.maybeParseUserAgentString(userAgent), null);
  }

  private double managerErrors(final String type) {
    return registry.find("chat.DynamicConfigurationManager.error").tag("type", type).counters().stream()
        .mapToDouble(Counter::count).sum();
  }

  private double monitorErrors(final String reason) {
    return registry.find("chat.FileObjectMonitor.error").tag("reason", reason).counters().stream()
        .mapToDouble(Counter::count).sum();
  }

  // ---- 改了文件，判定就变，不重启 ----

  @Test
  void editingTheFileChangesTheDecisionWithoutARestart() throws IOException {
    start(NO_RULES);
    assertThat(blocks(ANDROID)).as("no rules yet").isFalse();

    write(MINIMUM_175200);
    pollTimes(1);
    assertThat(blocks(ANDROID)).as("first sighting of the new file: not yet").isFalse();

    pollTimes(1);
    assertThat(blocks(ANDROID)).as("second poll: the rule is live").isTrue();

    write(MINIMUM_175000);
    pollTimes(2);
    assertThat(blocks(ANDROID)).as("lowering the minimum lifts the block").isFalse();

    assertThat(managerErrors("parse")).isZero();
    assertThat(managerErrors("validate")).isZero();
  }

  @Test
  void removingTheRuleFromTheFileLiftsTheBlock() throws IOException {
    start(MINIMUM_175200);
    assertThat(blocks(ANDROID)).isTrue();

    write(NO_RULES);
    pollTimes(2);

    assertThat(blocks(ANDROID)).isFalse();
  }

  // ---- 改坏了：保留上一份好的，并有指标 ----

  @Test
  void aFileWithBrokenYamlKeepsTheLastGoodConfigurationAndIsCounted() throws IOException {
    start(MINIMUM_175200);
    assertThat(blocks(ANDROID)).isTrue();

    write("captcha: {scoreFloor: 1.0\nremoteDeprecation: [unclosed");
    pollTimes(2);

    assertThat(blocks(ANDROID)).as("still the last good configuration").isTrue();
    assertThat(managerErrors("parse")).isEqualTo(1);

    // 改回好的：恢复
    write(MINIMUM_175000);
    pollTimes(2);
    assertThat(blocks(ANDROID)).isFalse();
  }

  @Test
  void aFileThatParsesButFailsValidationKeepsTheLastGoodConfigurationAndIsCounted() throws IOException {
    start(MINIMUM_175200);

    write("""
        captcha:
          scoreFloor: null
        remoteDeprecation:
          minimumBuilds:
            ANDROID: 1
        """);
    pollTimes(2);

    assertThat(blocks(ANDROID)).as("still the last good configuration (minimum 175200)").isTrue();
    assertThat(managerErrors("validate")).isEqualTo(1);
  }

  @Test
  void aBadValueKeepsTheLastGoodConfigurationAndIsCounted() throws IOException {
    start(MINIMUM_175200);

    write(NO_RULES + "remoteDeprecation:\n  minimumBuilds:\n    ANDROID: abc\n");
    pollTimes(2);
    assertThat(blocks(ANDROID)).isTrue();
    assertThat(managerErrors("parse")).isEqualTo(1);

    write(NO_RULES + "remoteDeprecation:\n  minimumBuilds:\n    android: 1\n");
    pollTimes(2);
    assertThat(blocks(ANDROID)).as("lower-case platform names are rejected as a whole").isTrue();
    assertThat(managerErrors("parse")).isEqualTo(2);
  }

  @Test
  void anEmptyFileKeepsTheLastGoodConfigurationAndIsCounted() throws IOException {
    start(MINIMUM_175200);

    write("");
    pollTimes(2);

    assertThat(blocks(ANDROID)).isTrue();
    assertThat(managerErrors("parse")).isEqualTo(1);
  }

  /// 运维大概率用中文写注释：文件按 UTF-8 读，注释里有中文不能让解析失败；Windows 编辑器留下的 CRLF 换行也一样
  @Test
  void chineseCommentsAndWindowsLineEndingsAreFine() throws IOException {
    start(NO_RULES);

    write("# 2026-10-01 最低构建号 175200：安全更新，见发版记录\n" + MINIMUM_175200);
    pollTimes(2);
    assertThat(blocks(ANDROID)).isTrue();

    write(MINIMUM_175000.replace("\n", "\r\n"));
    pollTimes(2);
    assertThat(blocks(ANDROID)).isFalse();

    assertThat(managerErrors("parse")).isZero();
    assertThat(managerErrors("validate")).isZero();
  }

  /// 「撤销」的手滑：把值删了、键留着，或者把整块的子项都注释掉。以前这是全站 NPE；现在等同于「没配」，block 解除
  @Test
  void blankingTheRuleOutIsTheSameAsRemovingIt() throws IOException {
    start(MINIMUM_175200);
    assertThat(blocks(ANDROID)).isTrue();

    write(NO_RULES + "remoteDeprecation:\n  minimumBuilds:\n    ANDROID:\n");
    pollTimes(2);
    assertThat(blocks(ANDROID)).as("value deleted, key left behind").isFalse();

    write(MINIMUM_175200);
    pollTimes(2);
    assertThat(blocks(ANDROID)).isTrue();

    write(NO_RULES + "remoteDeprecation:\n  # minimumBuilds:\n  #   ANDROID: 175200\n");
    pollTimes(2);
    assertThat(blocks(ANDROID)).as("block present but every child commented out").isFalse();
  }

  @Test
  void aDeletedFileKeepsTheLastGoodConfigurationAndIsCounted() throws IOException {
    start(MINIMUM_175200);

    Files.delete(file);
    pollTimes(3);

    assertThat(blocks(ANDROID)).as("still the last good configuration").isTrue();
    assertThat(monitorErrors("missing")).isEqualTo(3);

    // 文件回来了
    write(MINIMUM_175000);
    pollTimes(2);
    assertThat(blocks(ANDROID)).isFalse();
  }

  // ---- 首次启动 ----

  @Test
  void startingWithoutTheFileFailsFastInsteadOfUsingDefaults() {
    assertTimeoutPreemptively(Duration.ofSeconds(10), () ->
        assertThatThrownBy(() -> startWith(executor, Duration.ofSeconds(10)))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining(file.toString()));
  }

  /// 文件在、但首次就是坏的：`DynamicConfigurationManager.start()` 一直等到出现一份合法配置，绝不悄悄用缺省（上游的行为，这里钉住）
  @Test
  void startingWithAnInvalidFileWaitsForAValidOneInsteadOfUsingDefaults() throws Exception {
    write("not: [valid");

    // daemon 线程：上游的 start() 吞掉中断、会一直等——万一这个用例失败，线程也不能拖住整个 JVM
    final ExecutorService starter = Executors.newSingleThreadExecutor(runnable -> {
      final Thread thread = new Thread(runnable, "reload-test-starter");
      thread.setDaemon(true);
      return thread;
    });

    try {
      final CompletableFuture<Void> started =
          CompletableFuture.runAsync(() -> startWith(executor, Duration.ofSeconds(10)), starter);

      // 监控器把轮询任务交给调度器，说明首次读取和交付都做完了（此时它卡在「等一份合法配置」上）；再确认它确实还没放行
      final ArgumentCaptor<Runnable> task = ArgumentCaptor.forClass(Runnable.class);
      verify(executor, timeout(10_000)).scheduleAtFixedRate(task.capture(), anyLong(), anyLong(), any());
      Thread.sleep(300);
      assertThat(started).as("server start-up must not proceed on defaults").isNotDone();

      write(MINIMUM_175200);
      task.getValue().run();
      task.getValue().run();

      started.get(10, TimeUnit.SECONDS);
      assertThat(blocks(ANDROID)).isTrue();
    } finally {
      starter.shutdownNow();
    }
  }

  /// YAML 的根是 `~` / `null` / `---`：上游的 `parseConfiguration` 对它抛 `IllegalArgumentException`（HV000116），
  /// 而不是计一次 parse / validate 错误。首次启动：直接失败，服务起不来
  @Test
  void startingWithAFileWhoseYamlRootIsNullFailsFast() throws IOException {
    write("~\n");

    assertTimeoutPreemptively(Duration.ofSeconds(10), () ->
        assertThatThrownBy(() -> startWith(executor, Duration.ofSeconds(10)))
            .isInstanceOf(IllegalArgumentException.class));
  }

  /// 运行中才出现这样的文件：这一版被拒绝一次（一条 WARN、`error{reason=listener}` 计一次），仍是上一份好的；
  /// 同一版不再重复交付（以前每个间隔刷一条带栈的 WARN）；改对了照常生效
  @Test
  void aFileWhoseYamlRootIsNullIsRefusedOnceAndKeepsTheLastGoodConfiguration() throws IOException {
    start(MINIMUM_175200);

    write("~\n");
    pollTimes(2);
    assertThat(blocks(ANDROID)).as("still the last good configuration").isTrue();
    assertThat(monitorErrors("listener")).isEqualTo(1);

    pollTimes(5);
    assertThat(monitorErrors("listener")).as("the same version is not offered again").isEqualTo(1);
    assertThat(blocks(ANDROID)).isTrue();

    write(MINIMUM_175000);
    pollTimes(2);
    assertThat(blocks(ANDROID)).isFalse();
  }

  // ---- 真调度器 ----

  @Test
  void theRealSchedulerPicksUpAnEdit() throws Exception {
    final ScheduledExecutorService realExecutor = Executors.newSingleThreadScheduledExecutor();

    try {
      write(NO_RULES);
      assertTimeoutPreemptively(Duration.ofSeconds(10), () -> startWith(realExecutor, Duration.ofMillis(50)));
      assertThat(blocks(ANDROID)).isFalse();

      write(MINIMUM_175200);
      eventually(() -> blocks(ANDROID), Duration.ofSeconds(10));

      Files.delete(file);
      eventually(() -> monitorErrors("missing") > 0, Duration.ofSeconds(10));
      assertThat(blocks(ANDROID)).as("a deleted file does not change anything").isTrue();

      write(MINIMUM_175000);
      eventually(() -> !blocks(ANDROID), Duration.ofSeconds(10));
    } finally {
      realExecutor.shutdownNow();
    }
  }

  private static void eventually(final BooleanSupplier condition, final Duration timeout) throws InterruptedException {
    final long deadline = System.nanoTime() + timeout.toNanos();

    while (!condition.getAsBoolean()) {
      if (System.nanoTime() > deadline) {
        fail("condition not met within " + timeout);
      }
      Thread.sleep(10);
    }
  }
}
