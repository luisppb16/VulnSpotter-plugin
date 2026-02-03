/*
 * Copyright (c) 2026 Luis Paolo Pepe Barra (@LuisPPB16).
 * All rights reserved.
 */

package com.projectsapo.client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.projectsapo.model.OsvBatchResponse;
import com.projectsapo.model.OsvPackage;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.junit.jupiter.api.Test;

public class OsvClientBenchmarkTest {

    @Test
    public void benchmarkBatchRequest() throws Exception {
        int totalPackages = 1000;
        List<OsvPackage> packages = new ArrayList<>();
        for (int i = 0; i < totalPackages; i++) {
            packages.add(new OsvPackage("pkg-" + i, "Maven", "1.0." + i));
        }

        HttpClient httpClient = mock(HttpClient.class);
        HttpResponse<String> response = mock(HttpResponse.class);

        when(response.statusCode()).thenReturn(200);
        // We'll return an empty results list to avoid complex JSON parsing in the mock
        when(response.body()).thenReturn("{\"results\": []}");

        when(httpClient.send(any(), any())).thenAnswer(invocation -> {
            // Simulate API processing time: 0.2ms per package
            // For 1000 packages, it's 200ms
            // For 500 packages, it's 100ms

            // In a real scenario, we'd parse the request body to get the count.
            // For the benchmark, we'll assume the client is currently sending everything at once.
            // When we implement chunking, this mock will be called multiple times with smaller lists.

            // To make it work for both cases, we can try to estimate the count from the body if possible,
            // but for simplicity in the baseline, let's just sleep 200ms if we assume it's one big request.
            // Actually, let's try to be a bit smarter.

            Thread.sleep(100); // Fixed overhead per request
            return response;
        });

        ExecutorService executor = Executors.newCachedThreadPool();
        OsvClient client = new OsvClient(executor, httpClient);

        // Warmup
        for (int i = 0; i < 3; i++) {
            client.checkDependencies(packages).join();
        }

        long start = System.currentTimeMillis();
        int iterations = 5;
        for (int i = 0; i < iterations; i++) {
            client.checkDependencies(packages).join();
        }
        long duration = System.currentTimeMillis() - start;

        System.out.printf("Average duration for %d packages: %.2f ms%n", totalPackages, (double) duration / iterations);

        executor.shutdown();
    }
}
