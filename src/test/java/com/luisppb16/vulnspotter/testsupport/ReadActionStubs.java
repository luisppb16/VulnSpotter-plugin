/*
 * *****************************************************************************
 * Copyright (c)  2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 * *****************************************************************************
 */

package com.luisppb16.vulnspotter.testsupport;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.intellij.openapi.application.NonBlockingReadAction;
import com.intellij.openapi.application.ReadAction;
import java.util.concurrent.Callable;
import java.util.concurrent.Executor;
import java.util.function.Consumer;
import org.jetbrains.concurrency.CancellablePromise;
import org.mockito.MockedStatic;

/**
 * Test scaffolding shared by the scanner-service suites, so a platform-API workaround can never
 * drift between the copies: the stub encodes the 2026.2 {@code NonBlockingReadAction} contract,
 * which no longer exposes {@code executeSynchronously()} — the service completes through {@code
 * submit(Executor) → CancellablePromise}, and the stub fires the returned promise's onSuccess/
 * onError consumers synchronously so the suites run deterministically headless.
 */
public final class ReadActionStubs {

  private ReadActionStubs() {
    throw new UnsupportedOperationException("Utility class");
  }

  /** Installs the {@code nonBlocking → submit} stub on an open {@link MockedStatic}. */
  @SuppressWarnings("rawtypes")
  public static void installNonBlockingSubmitStub(MockedStatic<ReadAction> readActionMock) {
    readActionMock
        .when(() -> ReadAction.nonBlocking(any(Callable.class)))
        .thenAnswer(
            invocation -> {
              Callable<?> callable = invocation.getArgument(0);
              Attempt attempt = tryCall(callable);
              CancellablePromise<Object> promise = mock(CancellablePromise.class);
              when(promise.onSuccess(any(Consumer.class)))
                  .thenAnswer(
                      successInvocation -> {
                        if (attempt.failure() == null) {
                          Consumer<Object> consumer = successInvocation.getArgument(0);
                          consumer.accept(attempt.outcome());
                        }
                        return promise;
                      });
              when(promise.onError(any(Consumer.class)))
                  .thenAnswer(
                      errorInvocation -> {
                        if (attempt.failure() != null) {
                          Consumer<Throwable> consumer = errorInvocation.getArgument(0);
                          consumer.accept(attempt.failure());
                        }
                        return promise;
                      });
              NonBlockingReadAction<Object> action = mock(NonBlockingReadAction.class);
              when(action.submit(any(Executor.class))).thenReturn(promise);
              return action;
            });
  }

  /** Runs the callable synchronously and captures its outcome (or failure) as immutable state. */
  private static Attempt tryCall(Callable<?> callable) {
    try {
      return new Attempt(callable.call(), null);
    } catch (Throwable t) {
      return new Attempt(null, t);
    }
  }

  private record Attempt(Object outcome, Throwable failure) {}
}
