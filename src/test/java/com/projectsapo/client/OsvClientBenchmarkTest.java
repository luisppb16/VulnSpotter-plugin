/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.projectsapo.model.OsvPackage;
import java.io.FileWriter;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class OsvClientBenchmarkTest {

    @Test
    @SuppressWarnings("unchecked")
    void measureThreadUtilization() throws Exception {
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(2);
        HttpClient httpClient = mock(HttpClient.class);
        OsvClient client = new OsvClient(executor, httpClient);

        // Mock async behavior
        when(httpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class))).thenAnswer(invocation -> {
            // Simulate network I/O without blocking the calling thread
            return CompletableFuture.supplyAsync(() -> {
                HttpResponse<String> response = mock(HttpResponse.class);
                when(response.statusCode()).thenReturn(200);
                when(response.body()).thenReturn("{}");
                return response;
            }, CompletableFuture.delayedExecutor(500, TimeUnit.MILLISECONDS));
        });

        long startTime = System.currentTimeMillis();

        AtomicInteger activeThreadsDuringIO = new AtomicInteger(0);

        List<CompletableFuture<?>> futures = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            futures.add(client.checkDependencies(List.of(new OsvPackage("pkg" + i, "Maven", "1.0.0"))));
        }

        // Wait a bit for threads to start, do preparation and then trigger sendAsync
        Thread.sleep(200);
        activeThreadsDuringIO.set(executor.getActiveCount());

        @SuppressWarnings("rawtypes")
        CompletableFuture[] futuresArray = futures.toArray(new CompletableFuture[0]);
        CompletableFuture.allOf(futuresArray).join();
        long endTime = System.currentTimeMillis();

        String result = "Optimized (Async):\n" +
                        "Active threads during I/O: " + activeThreadsDuringIO.get() + "\n" +
                        "Total time: " + (endTime - startTime) + " ms\n";

        try (FileWriter writer = new FileWriter("benchmark_result.txt", true)) {
            writer.write(result);
        }

        executor.shutdown();
    }
}
