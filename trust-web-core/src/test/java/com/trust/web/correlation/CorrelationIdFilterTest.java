package com.trust.web.correlation;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioral tests for {@link CorrelationIdFilter}.
 * <p>
 * The header name ("X-Correlation-ID") and the MDC key ("correlationId") are hardcoded
 * here on purpose: they are the actual wire/log contract exposed to callers, so these
 * tests double as a lock on {@link CorrelationId}'s constant values.
 */
class CorrelationIdFilterTest {

    private static final String HEADER_NAME = "X-Correlation-ID";
    private static final String MDC_KEY = "correlationId";

    private final CorrelationIdFilter filter = new CorrelationIdFilter();

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void givenValidCorrelationIdHeader_whenFilterExecutes_thenValueIsPreservedInMdcDuringChainAndInResponseHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader(HEADER_NAME, "abc-123.def:456");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(mdcDuringChain.get()).isEqualTo("abc-123.def:456");
        assertThat(response.getHeader(HEADER_NAME)).isEqualTo("abc-123.def:456");
    }

    @Test
    void givenNoCorrelationIdHeader_whenFilterExecutes_thenUuidIsGeneratedAndAvailableInMdcDuringChainAndInResponseHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY));

        filter.doFilter(request, response, chain);

        String generated = response.getHeader(HEADER_NAME);
        assertThat(generated).isNotBlank();
        assertThatCode(() -> UUID.fromString(generated)).doesNotThrowAnyException();
        assertThat(mdcDuringChain.get()).isEqualTo(generated);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "invalid value with spaces",
            "invalid/value",
            "invalid@value",
            "invalid<script>value",
            "   "
    })
    void givenInvalidCorrelationIdHeader_whenFilterExecutes_thenNewUuidIsGeneratedAndInvalidValueIsNotPropagated(String invalidValue) throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader(HEADER_NAME, invalidValue);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> { };

        filter.doFilter(request, response, chain);

        String result = response.getHeader(HEADER_NAME);
        assertThat(result).isNotEqualTo(invalidValue);
        assertThatCode(() -> UUID.fromString(result)).doesNotThrowAnyException();
    }

    @Test
    void givenEmptyCorrelationIdHeader_whenFilterExecutes_thenNewUuidIsGenerated() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader(HEADER_NAME, "");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> { };

        filter.doFilter(request, response, chain);

        String result = response.getHeader(HEADER_NAME);
        assertThatCode(() -> UUID.fromString(result)).doesNotThrowAnyException();
    }

    @Test
    void givenCorrelationIdHeaderExceedingMaxAllowedLength_whenFilterExecutes_thenNewUuidIsGenerated() throws Exception {
        String tooLong = "a".repeat(129);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader(HEADER_NAME, tooLong);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> { };

        filter.doFilter(request, response, chain);

        String result = response.getHeader(HEADER_NAME);
        assertThat(result).isNotEqualTo(tooLong);
        assertThatCode(() -> UUID.fromString(result)).doesNotThrowAnyException();
    }

    @Test
    void givenCorrelationIdHeaderAtMaxAllowedLength_whenFilterExecutes_thenValueIsPreserved() throws Exception {
        String maxLengthValid = "a".repeat(128);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        request.addHeader(HEADER_NAME, maxLengthValid);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> { };

        filter.doFilter(request, response, chain);

        assertThat(response.getHeader(HEADER_NAME)).isEqualTo(maxLengthValid);
    }

    @Test
    void givenNormalRequestCompletion_whenFilterFinishes_thenMdcCorrelationIdIsRemoved() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> { };

        filter.doFilter(request, response, chain);

        assertThat(MDC.get(MDC_KEY)).isNull();
    }

    @Test
    void givenExceptionThrownInFilterChain_whenFilterExecutes_thenMdcCorrelationIdIsStillRemovedAndExceptionPropagates() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> {
            throw new IllegalStateException("downstream failure");
        };

        assertThatThrownBy(() -> filter.doFilter(request, response, chain))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("downstream failure");

        assertThat(MDC.get(MDC_KEY)).isNull();
    }
}
