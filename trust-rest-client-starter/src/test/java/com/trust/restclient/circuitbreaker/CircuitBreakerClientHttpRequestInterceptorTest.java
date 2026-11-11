package com.trust.restclient.circuitbreaker;

import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Behavioral tests for {@link CircuitBreakerClientHttpRequestInterceptor}:
 * does it genuinely stop calling a service once it looks unhealthy, and
 * just as importantly, does it correctly leave a healthy or merely
 * client-side-erroring service alone?
 */
class CircuitBreakerClientHttpRequestInterceptorTest {

    private static HttpRequest anyRequest() {
        HttpRequest request = mock(HttpRequest.class);
        given(request.getMethod()).willReturn(HttpMethod.GET);
        given(request.getURI()).willReturn(URI.create("http://downstream.example/resource"));
        return request;
    }

    private static ClientHttpResponse responseWithStatus(int statusCode) throws IOException {
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        given(response.getStatusCode()).willReturn(HttpStatusCode.valueOf(statusCode));
        return response;
    }

    private static CircuitBreakerClientHttpRequestInterceptor newInterceptor(
            String name, float failureRateThreshold, int slidingWindowSize, int minimumNumberOfCalls) {
        return new CircuitBreakerClientHttpRequestInterceptor(
                CircuitBreakerRegistry.ofDefaults(), name, failureRateThreshold, slidingWindowSize,
                minimumNumberOfCalls, Duration.ofSeconds(30), 3);
    }

    /** Same fake execution style as {@code RetryClientHttpRequestInterceptorTest}. */
    private static final class ScriptedExecution implements ClientHttpRequestExecution {

        private final Deque<Object> outcomes;
        private int callCount = 0;

        ScriptedExecution(List<Object> outcomes) {
            this.outcomes = new ArrayDeque<>(outcomes);
        }

        @Override
        public ClientHttpResponse execute(HttpRequest request, byte[] body) throws IOException {
            callCount++;
            Object outcome = outcomes.poll();
            if (outcome == null) {
                throw new IllegalStateException("No more scripted outcomes: unexpected extra call");
            }
            if (outcome instanceof IOException ioException) {
                throw ioException;
            }
            return (ClientHttpResponse) outcome;
        }
    }

    @Test
    void givenOnlySuccessfulResponses_whenIntercepting_thenTheCircuitStaysClosedAndEveryCallReachesTheTransport()
            throws Exception {
        CircuitBreakerClientHttpRequestInterceptor interceptor = newInterceptor("service-a", 50f, 4, 4);
        ScriptedExecution execution = new ScriptedExecution(List.of(
                responseWithStatus(200), responseWithStatus(200), responseWithStatus(200), responseWithStatus(200),
                responseWithStatus(200)));

        for (int i = 0; i < 5; i++) {
            ClientHttpResponse response = interceptor.intercept(anyRequest(), new byte[0], execution);
            assertThat(response.getStatusCode().value()).isEqualTo(200);
        }
        assertThat(execution.callCount).isEqualTo(5);
    }

    @Test
    void givenEnoughConsecutive5xxResponses_whenIntercepting_thenTheCircuitOpensAndRejectsWithoutReachingTheTransport()
            throws Exception {
        CircuitBreakerClientHttpRequestInterceptor interceptor = newInterceptor("service-b", 50f, 2, 2);
        ScriptedExecution execution = new ScriptedExecution(List.of(
                responseWithStatus(503), responseWithStatus(503)));

        interceptor.intercept(anyRequest(), new byte[0], execution);
        interceptor.intercept(anyRequest(), new byte[0], execution);

        assertThatThrownBy(() -> interceptor.intercept(anyRequest(), new byte[0], execution))
                .isInstanceOf(CallNotPermittedException.class);
        assertThat(execution.callCount)
                .as("the rejected call must never reach the transport")
                .isEqualTo(2);
    }

    @Test
    void givenOnly4xxResponses_whenIntercepting_thenTheyDoNotCountAsFailuresAndTheCircuitStaysClosed()
            throws Exception {
        CircuitBreakerClientHttpRequestInterceptor interceptor = newInterceptor("service-c", 50f, 2, 2);
        ScriptedExecution execution = new ScriptedExecution(List.of(
                responseWithStatus(404), responseWithStatus(404), responseWithStatus(404)));

        for (int i = 0; i < 3; i++) {
            ClientHttpResponse response = interceptor.intercept(anyRequest(), new byte[0], execution);
            assertThat(response.getStatusCode().value()).isEqualTo(404);
        }
        assertThat(execution.callCount)
                .as("a 4xx reflects the caller, not the target's health - must never open the circuit")
                .isEqualTo(3);
    }

    @Test
    void givenEnoughConsecutiveIOExceptions_whenIntercepting_thenTheCircuitOpens() {
        CircuitBreakerClientHttpRequestInterceptor interceptor = newInterceptor("service-d", 50f, 2, 2);
        IOException failure = new IOException("connection refused");
        ScriptedExecution execution = new ScriptedExecution(List.of(failure, failure));

        assertThatThrownBy(() -> interceptor.intercept(anyRequest(), new byte[0], execution)).isSameAs(failure);
        assertThatThrownBy(() -> interceptor.intercept(anyRequest(), new byte[0], execution)).isSameAs(failure);

        assertThatThrownBy(() -> interceptor.intercept(anyRequest(), new byte[0], execution))
                .isInstanceOf(CallNotPermittedException.class);
        assertThat(execution.callCount).isEqualTo(2);
    }

    @Test
    void givenFewerCallsThanTheMinimumRequired_whenAllOfThemFail_thenTheCircuitStaysClosed() throws Exception {
        CircuitBreakerClientHttpRequestInterceptor interceptor = newInterceptor("service-e", 50f, 10, 10);
        ScriptedExecution execution = new ScriptedExecution(List.of(
                responseWithStatus(503), responseWithStatus(503), responseWithStatus(503)));

        for (int i = 0; i < 3; i++) {
            interceptor.intercept(anyRequest(), new byte[0], execution);
        }

        // A 4th call must still reach the transport - the circuit has not
        // seen enough calls yet (minimumNumberOfCalls=10) to evaluate the
        // failure rate at all.
        ClientHttpResponse fourth = responseWithStatus(200);
        ScriptedExecution secondExecution = new ScriptedExecution(List.of(fourth));
        ClientHttpResponse result = interceptor.intercept(anyRequest(), new byte[0], secondExecution);
        assertThat(result).isSameAs(fourth);
    }

    /**
     * {@code @NoRetry} is implemented one layer above this interceptor (a
     * request attribute set by {@code NoRetryProcessor}, read by
     * {@code RetryClientHttpRequestInterceptor}), which this class has no
     * knowledge of - so a failing call is recorded here exactly like any
     * other, {@code @NoRetry} or not. This test locks that: opting a call
     * out of retry must never also opt it out of the circuit breaker's
     * health tracking.
     */
    @Test
    void givenCallsThatWouldBeAnnotatedNoRetryAtTheProxyLayer_whenTheyFail_thenThisInterceptorStillCountsThemAsFailures()
            throws Exception {
        CircuitBreakerClientHttpRequestInterceptor interceptor = newInterceptor("service-f", 50f, 2, 2);
        ScriptedExecution execution = new ScriptedExecution(List.of(
                responseWithStatus(503), responseWithStatus(503)));

        // This interceptor doesn't retry anything itself - it is oblivious
        // to @NoRetry - so these two calls are exactly what a @NoRetry
        // method's two individual invocations would look like from here.
        interceptor.intercept(anyRequest(), new byte[0], execution);
        interceptor.intercept(anyRequest(), new byte[0], execution);

        assertThatThrownBy(() -> interceptor.intercept(anyRequest(), new byte[0], execution))
                .isInstanceOf(CallNotPermittedException.class);
    }
}
