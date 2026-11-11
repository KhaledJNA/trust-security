package com.trust.restclient.circuitbreaker;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.time.Duration;

/**
 * Stops calling a downstream service once it looks unhealthy, instead of
 * letting every incoming request keep hitting it - protecting a service
 * that is already struggling from being hammered further, and letting it
 * recover.
 *
 * <p>A call counts as a failure for this purpose when it throws (a
 * connection-level {@link IOException}) or returns a {@code 5xx} response -
 * unlike {@link com.trust.restclient.retry.RetryClientHttpRequestInterceptor},
 * this is intentionally not configurable per status code: a broken service
 * is broken regardless of which specific {@code 5xx} it happens to return,
 * whereas a {@code 4xx} reflects the caller's request, not the service's
 * health, and must never open the circuit.
 *
 * <p>Applies to every HTTP method, including {@code POST}/{@code PATCH} and
 * calls annotated {@link com.trust.restclient.retry.NoRetry}: whether a
 * call is safe to retry is a different question from whether it should
 * count toward the target's observed health.
 *
 * <p>When wired alongside retry, this interceptor must sit outside it (see
 * {@code ServiceClientGroupConfigurer}) so that a transient failure fixed by a
 * retry never counts against the circuit - only the final, post-retry
 * outcome does.
 *
 * <p>The underlying {@link CircuitBreaker} instance is obtained from a
 * shared {@link CircuitBreakerRegistry} (one per application) rather than
 * created standalone, so that {@code resilience4j-micrometer}'s
 * {@code TaggedCircuitBreakerMetrics} - which discovers instances through
 * the registry, not individually - can expose circuit breaker state and
 * metrics for every HTTP service group in one place.
 */
public final class CircuitBreakerClientHttpRequestInterceptor implements ClientHttpRequestInterceptor {

    private final CircuitBreaker circuitBreaker;

    public CircuitBreakerClientHttpRequestInterceptor(
            CircuitBreakerRegistry circuitBreakerRegistry,
            String clientName,
            float failureRateThreshold,
            int slidingWindowSize,
            int minimumNumberOfCalls,
            Duration waitDurationInOpenState,
            int permittedNumberOfCallsInHalfOpenState) {
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .failureRateThreshold(failureRateThreshold)
                .slidingWindowSize(slidingWindowSize)
                .minimumNumberOfCalls(minimumNumberOfCalls)
                .waitDurationInOpenState(waitDurationInOpenState)
                .permittedNumberOfCallsInHalfOpenState(permittedNumberOfCallsInHalfOpenState)
                .recordResult(CircuitBreakerClientHttpRequestInterceptor::isUnhealthyResponse)
                .build();
        this.circuitBreaker = circuitBreakerRegistry.circuitBreaker(clientName, config);
    }

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution)
            throws IOException {
        try {
            return circuitBreaker.executeCallable(() -> execution.execute(request, body));
        } catch (IOException | RuntimeException e) {
            // RuntimeException here is almost always CallNotPermittedException
            // (the circuit is open) - a meaningful, distinct signal a caller
            // may want to catch specifically, so it is left unwrapped.
            throw e;
        } catch (Exception e) {
            throw new IOException("Unexpected failure while calling " + request.getURI(), e);
        }
    }

    private static boolean isUnhealthyResponse(Object result) {
        ClientHttpResponse response = (ClientHttpResponse) result;
        try {
            return response.getStatusCode().is5xxServerError();
        } catch (IOException e) {
            return true;
        }
    }
}
