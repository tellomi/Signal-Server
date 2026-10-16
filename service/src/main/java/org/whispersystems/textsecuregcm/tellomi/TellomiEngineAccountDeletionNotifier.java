/*
 * Copyright 2026 重庆半格智能科技有限公司
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.whispersystems.textsecuregcm.tellomi;

import static org.whispersystems.textsecuregcm.metrics.MetricsUtil.name;

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.Metrics;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.DoubleSupplier;
import java.util.function.Function;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.TellomiEngineDeletionConfiguration;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.tellomi.EngineDeletionClient.Outcome;
import org.whispersystems.textsecuregcm.tellomi.EngineDeletionClient.Result;
import org.whispersystems.textsecuregcm.tellomi.EngineDeletionOutbox.Entry;

/// Tells the content engine that a Signal account is gone (ADR-0071 §5.4, L2-5): `DELETE /internal/users/{sub}` with
/// `sub = TellomiFeedTokens.pseudonym(aci)`, the same derivation the credentials use.
///
/// Rules (see ACCOUNT-DELETION-ENGINE-DESIGN.md):
/// - after the first delete succeeded, a **second delete** is queued for `accountDeletedAt + secondDeleteDelay`
///   (default 70 minutes): a feed credential issued just before the deletion stays valid for up to an hour and the
///   engine cannot know the Signal account is gone. A new account that recycles the same ACI cancels it;
/// - **never in the way of the account deletion.** {@link #onAccountDeleted} runs after the account is already gone,
///   only puts the pseudonym into the outbox and never throws or blocks on the network;
/// - the actual calls run on the notifier's own executor thread ({@link #start}) or from {@link #drain};
/// - success (200, and 404 / 410 as configured) completes the entry; network errors, timeouts, 5xx, 429 are retried
///   with exponential backoff and jitter up to `maxAttempts`, then dead-lettered; other 4xx, 401 / 403 and redirects are
///   dead-lettered at once and audited, never retried automatically;
/// - logs and metrics carry an outcome, an HTTP status, an attempt count and a random entry id, **never** the ACI, the
///   pseudonym, the URL, the key, or the engine's response body.
public class TellomiEngineAccountDeletionNotifier implements AccountsManager.AccountDeletionListener {

  /// anything the engine can answer with
  @FunctionalInterface
  public interface Sender {
    Result delete(byte[] sub);
  }

  private static final Logger log = LoggerFactory.getLogger(TellomiEngineAccountDeletionNotifier.class);

  private static final String ENQUEUED_COUNTER = name(TellomiEngineAccountDeletionNotifier.class, "enqueued");
  private static final String ATTEMPT_COUNTER = name(TellomiEngineAccountDeletionNotifier.class, "attempt");
  private static final String RESULT_COUNTER = name(TellomiEngineAccountDeletionNotifier.class, "result");
  private static final String NOT_FOUND_ASSUMED_COUNTER =
      name(TellomiEngineAccountDeletionNotifier.class, "notFoundAssumedDeleted");
  private static final String SWEEP_SCHEDULED_COUNTER = name(TellomiEngineAccountDeletionNotifier.class, "sweepScheduled");
  private static final String SWEEP_NOT_SCHEDULED_COUNTER =
      name(TellomiEngineAccountDeletionNotifier.class, "sweepNotScheduled");
  private static final String SWEEP_CANCELLED_COUNTER = name(TellomiEngineAccountDeletionNotifier.class, "sweepCancelled");
  private static final String PENDING_GAUGE = name(TellomiEngineAccountDeletionNotifier.class, "pending");
  private static final String DEAD_LETTER_GAUGE = name(TellomiEngineAccountDeletionNotifier.class, "deadLetter");

  /// entries tried in one round
  static final int BATCH_SIZE = 50;

  private final Function<UUID, byte[]> pseudonym;
  private final EngineDeletionOutbox outbox;
  private final Sender sender;
  private final Clock clock;
  private final DoubleSupplier jitter;
  private final int maxAttempts;
  private final Duration initialBackoff;
  private final Duration maxBackoff;
  private final Duration pollInterval;
  private final Duration secondDeleteDelay;
  private final ScheduledExecutorService executor;

  private final AtomicBoolean notFoundWarned = new AtomicBoolean();
  private final AtomicBoolean authFailedLogged = new AtomicBoolean();

  /// @param pseudonym derives the engine `sub` from an ACI (`TellomiFeedTokens::pseudonym`)
  /// @param jitter    values in `[0, 1)`; `ThreadLocalRandom.current()::nextDouble` in production
  /// @param executor  runs {@link #drain}; `null` in tests that call {@link #drain} themselves
  public TellomiEngineAccountDeletionNotifier(final TellomiEngineDeletionConfiguration config,
      final Function<UUID, byte[]> pseudonym,
      final EngineDeletionOutbox outbox,
      final Sender sender,
      final Clock clock,
      final DoubleSupplier jitter,
      final ScheduledExecutorService executor) {

    this.pseudonym = pseudonym;
    this.outbox = outbox;
    this.sender = sender;
    this.clock = clock;
    this.jitter = jitter;
    this.maxAttempts = config.maxAttempts();
    this.initialBackoff = config.initialBackoff();
    this.maxBackoff = config.maxBackoff();
    this.pollInterval = config.pollInterval();
    this.secondDeleteDelay = config.secondDeleteDelay();
    this.executor = executor;

    Gauge.builder(PENDING_GAUGE, outbox, EngineDeletionOutbox::pendingCount).register(Metrics.globalRegistry);
    Gauge.builder(DEAD_LETTER_GAUGE, outbox, EngineDeletionOutbox::deadLetterCount).register(Metrics.globalRegistry);
  }

  /// Starts the periodic drain. Does nothing without an executor.
  public void start() {
    if (executor != null) {
      executor.scheduleWithFixedDelay(this::drainQuietly, pollInterval.toMillis(), pollInterval.toMillis(),
          TimeUnit.MILLISECONDS);
    }
  }

  /// Called by `AccountsManager` after the account has been deleted. Never throws, never does network I/O.
  @Override
  public void onAccountDeleted(final UUID accountIdentifier) {
    try {
      final boolean accepted = outbox.enqueue(pseudonym.apply(accountIdentifier), clock.instant());
      if (accepted) {
        Metrics.counter(ENQUEUED_COUNTER).increment();
        if (executor != null) {
          executor.execute(this::drainQuietly);
        }
      } else {
        Metrics.counter(RESULT_COUNTER, "kind", "delete", "result", "dropped").increment();
        log.error("Tellomi engine deletion: outbox full, a deletion notice was dropped; reconciliation must cover it");
      }
    } catch (final Exception e) {
      // must not break account deletion; Errors (OutOfMemoryError, …) are not swallowed
      Metrics.counter(RESULT_COUNTER, "kind", "delete", "result", "dropped").increment();
      log.error("Tellomi engine deletion: could not queue a deletion notice ({})", e.getClass().getSimpleName());
    }
  }

  /// The ACI (hence the pseudonym) was recycled by a new account: a pending second delete would erase that account's
  /// data, so it is cancelled. A pending first delete is not (see the design doc, re-registration). Never throws.
  @Override
  public void onAccountCreatedWithRecycledAci(final UUID accountIdentifier) {
    try {
      if (outbox.cancelSweep(pseudonym.apply(accountIdentifier))) {
        Metrics.counter(SWEEP_CANCELLED_COUNTER).increment();
        log.info("Tellomi engine deletion: a pending second delete was cancelled (the account identifier was recycled)");
      }
    } catch (final Exception e) {
      log.error("Tellomi engine deletion: could not cancel a second delete ({})", e.getClass().getSimpleName());
    }
  }

  private void drainQuietly() {
    try {
      drain();
    } catch (final Throwable t) {
      log.error("Tellomi engine deletion: drain failed ({})", t.getClass().getSimpleName());
    }
  }

  /// One round: try every due entry (at most {@value #BATCH_SIZE}). The round stops after the first retryable failure
  /// (the engine is probably down; do not spend an attempt of every queued entry on it). Returns the number of entries
  /// attempted.
  public synchronized int drain() {
    final List<Entry> due = outbox.due(clock.instant(), BATCH_SIZE);
    int attempted = 0;
    for (final Entry entry : due) {
      attempted++;
      Result result;
      try {
        result = sender.delete(entry.sub());
      } catch (final RuntimeException e) {
        // a sender must not throw; if it does, it counts as a failed attempt rather than a hot loop
        result = new Result(Outcome.RETRY, 0, Optional.empty());
      }
      Metrics.counter(ATTEMPT_COUNTER, "kind", kindTag(entry), "outcome",
          result.outcome().name().toLowerCase(java.util.Locale.ROOT)).increment();
      final int attempts = entry.attempts() + 1;

      switch (result.outcome()) {
        case DELETED -> finish(entry, attempts, result, "deleted");
        case ALREADY_GONE -> {
          if (result.status() == 404) {
            Metrics.counter(NOT_FOUND_ASSUMED_COUNTER).increment();
            if (notFoundWarned.compareAndSet(false, true)) {
              log.warn("Tellomi engine deletion: the engine answered 404 and it was counted as already deleted "
                  + "(notFoundMeansDeleted). The real engine answers 404 on /internal when it has no service key "
                  + "configured, in which case nothing was deleted; watch the notFoundAssumedDeleted counter");
            }
          }
          finish(entry, attempts, result, "already_gone");
        }
        case RETRY -> {
          if (attempts >= maxAttempts) {
            deadLetter(entry, attempts, result, "retries_exhausted");
          } else {
            final Duration delay = backoff(attempts, result.retryAfter());
            outbox.reschedule(entry.entryId(), attempts, clock.instant().plus(delay), "retry_" + result.status());
            log.info("Tellomi engine deletion: entry={} attempt={} status={} retry_in_s={}", entry.entryId(),
                attempts, result.status(), delay.toSeconds());
          }
          return attempted;
        }
        case AUTH_FAILED -> {
          if (authFailedLogged.compareAndSet(false, true)) {
            log.error("Tellomi engine deletion: the engine rejected the service credentials (status {}); "
                + "deletion notices are dead-lettered until the key is fixed and they are requeued", result.status());
          }
          deadLetter(entry, attempts, result, "auth_failed");
        }
        case PERMANENT -> deadLetter(entry, attempts, result, "permanent_" + result.status());
      }
    }
    return attempted;
  }

  private static String kindTag(final Entry entry) {
    return entry.kind() == EngineDeletionOutbox.Kind.SWEEP ? "sweep" : "delete";
  }

  private void finish(final Entry entry, final int attempts, final Result result, final String how) {
    outbox.complete(entry.entryId());
    Metrics.counter(RESULT_COUNTER, "kind", kindTag(entry), "result", "delivered").increment();
    log.info("Tellomi engine deletion: entry={} kind={} result={} status={} attempts={} age_s={}", entry.entryId(),
        kindTag(entry), how, result.status(), attempts,
        Duration.between(entry.enqueuedAt(), clock.instant()).toSeconds());
    if (entry.kind() == EngineDeletionOutbox.Kind.DELETE) {
      scheduleSecondDelete(entry);
    }
  }

  /// Queues the second delete for `accountDeletedAt + secondDeleteDelay` (immediately if that is already past). One
  /// entry per pseudonym and it never schedules another, so this is bounded; failing to schedule it (outbox full,
  /// something throws) costs only the second delete, never the first.
  private void scheduleSecondDelete(final Entry deleted) {
    if (secondDeleteDelay.isZero()) {
      return;
    }
    try {
      final Instant now = clock.instant();
      final Instant due = deleted.enqueuedAt().plus(secondDeleteDelay);
      if (outbox.enqueueSweep(deleted.sub(), due.isBefore(now) ? now : due, deleted.enqueuedAt())) {
        Metrics.counter(SWEEP_SCHEDULED_COUNTER).increment();
      } else {
        Metrics.counter(SWEEP_NOT_SCHEDULED_COUNTER).increment();
        log.warn("Tellomi engine deletion: the second delete could not be scheduled (outbox full or entry exists)");
      }
    } catch (final RuntimeException e) {
      Metrics.counter(SWEEP_NOT_SCHEDULED_COUNTER).increment();
      log.warn("Tellomi engine deletion: the second delete could not be scheduled ({})", e.getClass().getSimpleName());
    }
  }

  private void deadLetter(final Entry entry, final int attempts, final Result result, final String reason) {
    outbox.deadLetter(entry.entryId(), attempts, reason);
    Metrics.counter(RESULT_COUNTER, "kind", kindTag(entry), "result", "dead_letter").increment();
    log.warn("Tellomi engine deletion: entry={} kind={} result=dead_letter reason={} status={} attempts={} age_s={}",
        entry.entryId(), kindTag(entry), reason, result.status(), attempts,
        Duration.between(entry.enqueuedAt(), clock.instant()).toSeconds());
  }

  /// `initialBackoff * 2^(attempts-1)`, capped at `maxBackoff`, then "equal jitter": a random point in the upper half,
  /// so two retries never land at the same instant. The engine's `Retry-After`, when longer, wins.
  Duration backoff(final int attempts, final Optional<Duration> retryAfter) {
    final int shift = Math.min(Math.max(attempts - 1, 0), 30);
    Duration exp;
    try {
      exp = initialBackoff.multipliedBy(1L << shift);
    } catch (final ArithmeticException e) {
      exp = maxBackoff;
    }
    if (exp.compareTo(maxBackoff) > 0 || exp.isNegative()) {
      exp = maxBackoff;
    }
    final double factor = 0.5 + 0.5 * Math.min(Math.max(jitter.getAsDouble(), 0.0), 0.999999);
    Duration delay = Duration.ofMillis((long) (exp.toMillis() * factor));
    if (retryAfter.isPresent() && retryAfter.get().compareTo(delay) > 0) {
      delay = retryAfter.get();
    }
    return delay;
  }

  /// For operator tooling and tests.
  public EngineDeletionOutbox outbox() {
    return outbox;
  }
}
