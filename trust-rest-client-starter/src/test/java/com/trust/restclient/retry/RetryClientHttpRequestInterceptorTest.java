package com.trust.restclient.retry;

import io.github.resilience4j.retry.RetryRegistry;
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
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Behavioral tests for {@link RetryClientHttpRequestInterceptor}: verifies
 * the exact conditions under which a call is retried, and - just as
 * importantly - the conditions under which it deliberately is not.
 */
class RetryClientHttpRequestInterceptorTest {

    private static final Duration NO_DELAY = Duration.ofMillis(1);
    private static final Set<Integer> DEFAULT_RETRYABLE_STATUS_CODES = Set.of(502, 503, 504);

    private static HttpRequest requestFor(HttpMethod method) {
        HttpRequest request = mock(HttpRequest.class);
        given(request.getMethod()).willReturn(method);
        given(request.getURI()).willReturn(URI.create("http://downstream.example/resource"));
        return request;
    }

    private static ClientHttpResponse responseWithStatus(int statusCode) throws IOException {
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        given(response.getStatusCode()).willReturn(HttpStatusCode.valueOf(statusCode));
        return response;
    }

    /**
     * A hand-rolled fake rather than a Mockito mock: {@link ClientHttpRequestExecution}
     * is invoked repeatedly by the retry, and each invocation must return a
     * different, distinguishable outcome (thrown exception or given response) -
     * easier to express as a scripted sequence than as stubbed matchers.
     */
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
    void givenATransientIOExceptionThenSuccess_whenIntercepting_thenItRetriesOnceAndReturnsTheSuccessfulResponse()
            throws Exception {
        ClientHttpResponse success = responseWithStatus(200);
        ScriptedExecution execution = new ScriptedExecution(List.of(
                new IOException("connection reset"),
                success));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, DEFAULT_RETRYABLE_STATUS_CODES);

        ClientHttpResponse result = interceptor.intercept(requestFor(HttpMethod.GET), new byte[0], execution);

        assertThat(result).isSameAs(success);
        assertThat(execution.callCount).isEqualTo(2);
    }

    @Test
    void givenPersistentIOException_whenIntercepting_thenItStopsAfterMaxAttemptsAndRethrowsTheFailure() {
        IOException persistentFailure = new IOException("connection refused");
        ScriptedExecution execution = new ScriptedExecution(List.of(
                persistentFailure, persistentFailure, persistentFailure));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, DEFAULT_RETRYABLE_STATUS_CODES);

        assertThatThrownBy(() -> interceptor.intercept(requestFor(HttpMethod.GET), new byte[0], execution))
                .isSameAs(persistentFailure);
        assertThat(execution.callCount).isEqualTo(3);
    }

    @Test
    void given503OnEveryAttempt_whenIntercepting_thenItStopsAfterMaxAttemptsAndReturnsTheLastResponseAsIs()
            throws Exception {
        ClientHttpResponse first = responseWithStatus(503);
        ClientHttpResponse second = responseWithStatus(503);
        ClientHttpResponse third = responseWithStatus(503);
        ScriptedExecution execution = new ScriptedExecution(List.of(first, second, third));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, DEFAULT_RETRYABLE_STATUS_CODES);

        ClientHttpResponse result = interceptor.intercept(requestFor(HttpMethod.GET), new byte[0], execution);

        assertThat(result).isSameAs(third);
        assertThat(result.getStatusCode().value()).isEqualTo(503);
        assertThat(execution.callCount).isEqualTo(3);
        verify(first).close();
        verify(second).close();
        verify(third, never()).close();
    }

    @Test
    void given400Response_whenIntercepting_thenItIsNotRetried() throws Exception {
        ClientHttpResponse badRequest = responseWithStatus(400);
        ScriptedExecution execution = new ScriptedExecution(List.of(badRequest));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, DEFAULT_RETRYABLE_STATUS_CODES);

        ClientHttpResponse result = interceptor.intercept(requestFor(HttpMethod.GET), new byte[0], execution);

        assertThat(result).isSameAs(badRequest);
        assertThat(execution.callCount).isEqualTo(1);
    }

    @Test
    void givenAPostRequest_whenExecutionAlwaysFailsWith503_thenItIsNeverRetried() throws Exception {
        ClientHttpResponse serviceUnavailable = responseWithStatus(503);
        ScriptedExecution execution = new ScriptedExecution(List.of(serviceUnavailable));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, DEFAULT_RETRYABLE_STATUS_CODES);

        ClientHttpResponse result = interceptor.intercept(requestFor(HttpMethod.POST), new byte[0], execution);

        assertThat(result).isSameAs(serviceUnavailable);
        assertThat(execution.callCount).isEqualTo(1);
        verify(serviceUnavailable, never()).close();
    }

    @Test
    void givenAPostRequestThatThrowsAnIOException_whenIntercepting_thenItIsNeverRetriedEither() {
        IOException failure = new IOException("connection reset");
        ScriptedExecution execution = new ScriptedExecution(List.of(failure));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, DEFAULT_RETRYABLE_STATUS_CODES);

        assertThatThrownBy(() -> interceptor.intercept(requestFor(HttpMethod.POST), new byte[0], execution))
                .isSameAs(failure);
        assertThat(execution.callCount).isEqualTo(1);
    }

    @Test
    void given500Response_whenIntercepting_thenItIsNotRetriedByDefault() throws Exception {
        ClientHttpResponse internalServerError = responseWithStatus(500);
        ScriptedExecution execution = new ScriptedExecution(List.of(internalServerError));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, DEFAULT_RETRYABLE_STATUS_CODES);

        ClientHttpResponse result = interceptor.intercept(requestFor(HttpMethod.GET), new byte[0], execution);

        assertThat(result).isSameAs(internalServerError);
        assertThat(execution.callCount).isEqualTo(1);
    }

    @Test
    void given500ResponseWithACustomRetryableStatusSet_whenIntercepting_thenItIsRetried() throws Exception {
        ClientHttpResponse firstAttempt = responseWithStatus(500);
        ClientHttpResponse secondAttempt = responseWithStatus(200);
        ScriptedExecution execution = new ScriptedExecution(List.of(firstAttempt, secondAttempt));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, Set.of(500));

        ClientHttpResponse result = interceptor.intercept(requestFor(HttpMethod.GET), new byte[0], execution);

        assertThat(result).isSameAs(secondAttempt);
        assertThat(execution.callCount).isEqualTo(2);
    }

    @Test
    void given503ResponseButRetryableStatusSetDoesNotIncludeIt_whenIntercepting_thenItIsNotRetried()
            throws Exception {
        ClientHttpResponse serviceUnavailable = responseWithStatus(503);
        ScriptedExecution execution = new ScriptedExecution(List.of(serviceUnavailable));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 3, NO_DELAY, Set.of(504));

        ClientHttpResponse result = interceptor.intercept(requestFor(HttpMethod.GET), new byte[0], execution);

        assertThat(result).isSameAs(serviceUnavailable);
        assertThat(execution.callCount).isEqualTo(1);
    }

    @Test
    void givenMaxAttemptsOfOne_whenExecutionFailsWithATransientIOException_thenItIsNotRetried() {
        IOException failure = new IOException("timeout");
        ScriptedExecution execution = new ScriptedExecution(List.of(failure));
        RetryClientHttpRequestInterceptor interceptor =
                new RetryClientHttpRequestInterceptor(RetryRegistry.ofDefaults(), "downstream", 1, NO_DELAY, DEFAULT_RETRYABLE_STATUS_CODES);

        assertThatThrownBy(() -> interceptor.intercept(requestFor(HttpMethod.GET), new byte[0], execution))
                .isSameAs(failure);
        assertThat(execution.callCount).isEqualTo(1);
    }
}
