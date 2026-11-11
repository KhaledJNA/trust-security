package com.trust.security.web.problem;

import com.trust.web.problem.ProblemDetailsWriter;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Behavioral tests for {@link ProblemDetailsAuthenticationEntryPoint}, using
 * a real {@link ProblemDetailsWriter} so the JSON body assertions exercise
 * the actual writer contract.
 */
class ProblemDetailsAuthenticationEntryPointTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ProblemDetailsWriter problemDetailsWriter = new ProblemDetailsWriter(objectMapper);

    private static AuthenticationException authenticationException() {
        return new AuthenticationException("not authenticated") {
        };
    }

    @Test
    void givenNullDelegate_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new ProblemDetailsAuthenticationEntryPoint(null, problemDetailsWriter));
    }

    @Test
    void givenNullProblemDetailsWriter_whenConstructing_thenNullPointerExceptionIsThrown() {
        AuthenticationEntryPoint delegate = mock(AuthenticationEntryPoint.class);
        assertThatNullPointerException()
                .isThrownBy(() -> new ProblemDetailsAuthenticationEntryPoint(delegate, null));
    }

    @Test
    void givenDelegateSetsStatusAndWwwAuthenticateHeader_whenCommencing_thenBothArePreservedAndProblemBodyReflectsTheStatus() throws Exception {
        AuthenticationEntryPoint delegate = (req, res, ex) -> {
            res.setStatus(401);
            res.setHeader("WWW-Authenticate", "Bearer");
        };
        ProblemDetailsAuthenticationEntryPoint entryPoint =
                new ProblemDetailsAuthenticationEntryPoint(delegate, problemDetailsWriter);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, authenticationException());

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo("Bearer");

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(401);
        assertThat(body.get("detail").asString()).isEqualTo("Authentication is required to access this resource.");
        assertThat(response.getContentType()).isEqualTo("application/problem+json;charset=UTF-8");
    }

    @Test
    void givenDelegateRunsBeforeWritingTheBody_whenCommencing_thenDelegateIsInvokedFirst() throws Exception {
        AuthenticationEntryPoint delegate = mock(AuthenticationEntryPoint.class);
        ProblemDetailsAuthenticationEntryPoint entryPoint =
                new ProblemDetailsAuthenticationEntryPoint(delegate, problemDetailsWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthenticationException exception = authenticationException();

        entryPoint.commence(request, response, exception);

        verify(delegate).commence(request, response, exception);
    }

    @Test
    void givenDelegateThrows_whenCommencing_thenExceptionPropagatesAndProblemDetailsWriterIsNeverCalled() throws Exception {
        AuthenticationEntryPoint delegate = mock(AuthenticationEntryPoint.class);
        willThrow(new IOException("delegate failure"))
                .given(delegate).commence(any(), any(), any());
        ProblemDetailsAuthenticationEntryPoint entryPoint =
                new ProblemDetailsAuthenticationEntryPoint(delegate, problemDetailsWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> entryPoint.commence(request, response, authenticationException()))
                .isInstanceOf(IOException.class)
                .hasMessage("delegate failure");

        assertThat(response.getContentAsString()).isEmpty();
    }

    @Test
    void givenResponseAlreadyCommittedByDelegate_whenCommencing_thenProblemDetailsWriterDoesNotOverrideTheBody() throws Exception {
        AuthenticationEntryPoint delegate = (req, res, ex) -> {
            res.getWriter().write("delegate body");
            res.flushBuffer();
        };
        ProblemDetailsAuthenticationEntryPoint entryPoint =
                new ProblemDetailsAuthenticationEntryPoint(delegate, problemDetailsWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        entryPoint.commence(request, response, authenticationException());

        assertThat(response.getContentAsString()).isEqualTo("delegate body");
    }
}
