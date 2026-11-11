package com.trust.restclient.retry;

import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.time.Duration;
import java.util.Set;

/**
 * Retries a call to a downstream service on a transient failure - a
 * connection-level {@link IOException} (refused connection, timeout, DNS
 * failure) or a response whose status is in {@code retryableStatusCodes} -
 * with a fixed delay between attempts.
 *
 * <p>Only applied to HTTP methods HTTP itself defines as safe to repeat
 * ({@code GET}, {@code HEAD}, {@code OPTIONS}, {@code PUT}, {@code DELETE}).
 * {@code POST}/{@code PATCH} calls are never retried here: a transient
 * failure on those may have already mutated state on the target service,
 * and retrying blindly would risk a duplicate side effect.
 *
 * <p>If every attempt keeps failing with a retryable status, the last
 * response is returned as-is (not turned into an exception) so that normal
 * response handling downstream - including a future error-mapping
 * interceptor - still sees the real, final outcome.
 *
 * <p>A call made through a client interface method annotated {@link NoRetry}
 * bypasses this interceptor entirely, regardless of its HTTP method - see
 * {@link NoRetryProcessor}.
 *
 * <p>The underlying {@link Retry} instance is obtained from a shared
 * {@link RetryRegistry} (one per application) rather than created standalone,
 * so that {@code resilience4j-micrometer}'s {@code TaggedRetryMetrics} -
 * which discovers instances through the registry, not individually - can
 * expose retry metrics for every HTTP service group in one place.
 */
public final class RetryClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private static final Set<HttpMethod> RETRYABLE_METHODS =
            Set.of(HttpMethod.GET, HttpMethod.HEAD, HttpMethod.OPTIONS, HttpMethod.PUT, HttpMethod.DELETE);

    private final Retry retry;

    public RetryClientHttpRequestInterceptor(
            RetryRegistry retryRegistry, String groupName, int maxAttempts, Duration waitDuration,
            Set<Integer> retryableStatusCodes) {
        RetryConfig config = RetryConfig.<ClientHttpResponse>custom()
                .maxAttempts(maxAttempts)
                .waitDuration(waitDuration)
                .retryOnException(RetryClientHttpRequestInterceptor::isTransientTransportFailure)
                .retryOnResult(response -> isRetryableStatus(response, retryableStatusCodes))
                .consumeResultBeforeRetryAttempt((attempt, response) -> response.close())
                .build();
        this.retry = retryRegistry.retry(groupName, config);
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {

        if (NoRetryProcessor.isSuppressed(request) || !RETRYABLE_METHODS.contains(request.getMethod())) {
            return execution.execute(request, body);
        }

        try {
            return retry.executeCallable(() -> execution.execute(request, body));
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("Unexpected failure while retrying the call to " + request.getURI(), e);
        }
    }

    private static boolean isTransientTransportFailure(Throwable throwable) {
        return throwable instanceof IOException;
    }

    private static boolean isRetryableStatus(ClientHttpResponse response, Set<Integer> retryableStatusCodes) {
        try {
            return retryableStatusCodes.contains(response.getStatusCode().value());
        } catch (IOException e) {
            return false;
        }
    }
}
