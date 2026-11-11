package com.trust.restclient.tokenrelay;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.web.service.invoker.HttpRequestValues;

import java.lang.reflect.Method;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unlike {@code @NoRetry} (method-only), {@link NoTokenRelay} may forbid
 * relay per-client (on the interface) as well as per-method - this is the
 * behavior distinguishing this processor from {@code NoRetryProcessor}, so
 * both placements are exercised here.
 */
class NoTokenRelayProcessorTest {

    interface PlainClient {
        void call();

        @NoTokenRelay
        void annotatedMethod();
    }

    @NoTokenRelay
    interface AnnotatedClient {
        void call();
    }

    private static MockClientHttpRequest requestCarrying(Method method) {
        HttpRequestValues.Builder builder = HttpRequestValues.builder();
        NoTokenRelayProcessor.INSTANCE.process(method, new org.springframework.core.MethodParameter[0], null, builder);

        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        request.getAttributes().putAll(builder.build().getAttributes());
        return request;
    }

    @Test
    void givenPlainMethod_whenProcessed_thenNotSuppressed() throws Exception {
        Method method = PlainClient.class.getMethod("call");

        assertThat(NoTokenRelayProcessor.isSuppressed(requestCarrying(method))).isFalse();
    }

    @Test
    void givenMethodAnnotated_whenProcessed_thenSuppressed() throws Exception {
        Method method = PlainClient.class.getMethod("annotatedMethod");

        assertThat(NoTokenRelayProcessor.isSuppressed(requestCarrying(method))).isTrue();
    }

    @Test
    void givenDeclaringInterfaceAnnotated_whenProcessed_thenSuppressedEvenForAnUnannotatedMethod() throws Exception {
        Method method = AnnotatedClient.class.getMethod("call");

        assertThat(NoTokenRelayProcessor.isSuppressed(requestCarrying(method))).isTrue();
    }
}
