package com.trust.restclient.correlation;

import com.trust.web.correlation.CorrelationId;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class CorrelationIdClientHttpRequestInterceptorTest {

    private final CorrelationIdClientHttpRequestInterceptor interceptor =
            new CorrelationIdClientHttpRequestInterceptor();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void givenCorrelationIdInMdc_whenIntercepting_thenHeaderIsAddedToTheOutgoingRequest() throws Exception {
        MDC.put(CorrelationId.MDC_KEY, "abc-123");
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        given(execution.execute(request, body)).willReturn(response);

        ClientHttpResponse result = interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().getFirst(CorrelationId.HEADER_NAME)).isEqualTo("abc-123");
        assertThat(result).isSameAs(response);
    }

    @Test
    void givenNoCorrelationIdInMdc_whenIntercepting_thenOneIsGeneratedAndPropagated() throws Exception {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().getFirst(CorrelationId.HEADER_NAME)).isNotBlank();
    }

    @Test
    void givenNoCorrelationIdInMdc_whenIntercepting_thenGeneratedValueIsInMdcDuringTheCallOnly() throws Exception {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        String[] mdcDuringCall = new String[1];
        ClientHttpRequestExecution execution = (req, b) -> {
            mdcDuringCall[0] = MDC.get(CorrelationId.MDC_KEY);
            return mock(ClientHttpResponse.class);
        };

        interceptor.intercept(request, body, execution);

        assertThat(mdcDuringCall[0]).isEqualTo(request.getHeaders().getFirst(CorrelationId.HEADER_NAME));
        assertThat(MDC.get(CorrelationId.MDC_KEY))
                .as("the generated value must not be left behind after the call returns")
                .isNull();
    }

    @Test
    void givenBlankCorrelationIdInMdc_whenIntercepting_thenOneIsGeneratedAsIfMdcWereEmpty() throws Exception {
        MDC.put(CorrelationId.MDC_KEY, "   ");
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().getFirst(CorrelationId.HEADER_NAME)).isNotBlank();
    }

    @Test
    void givenRequestAlreadyHasCorrelationHeader_whenIntercepting_thenMdcValueOverwritesIt() throws Exception {
        MDC.put(CorrelationId.MDC_KEY, "from-mdc");
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        request.getHeaders().set(CorrelationId.HEADER_NAME, "stale-value");
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().getFirst(CorrelationId.HEADER_NAME)).isEqualTo("from-mdc");
    }

    @Test
    void whenIntercepting_thenTheRequestIsExecutedExactlyOnce() throws Exception {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        verify(execution, times(1)).execute(request, body);
    }
}
