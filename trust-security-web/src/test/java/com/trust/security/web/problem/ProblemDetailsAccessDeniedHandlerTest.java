package com.trust.security.web.problem;

import com.trust.web.problem.ProblemDetailsWriter;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
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
 * Behavioral tests for {@link ProblemDetailsAccessDeniedHandler}, using a
 * real {@link ProblemDetailsWriter} so the JSON body assertions exercise the
 * actual writer contract.
 */
class ProblemDetailsAccessDeniedHandlerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ProblemDetailsWriter problemDetailsWriter = new ProblemDetailsWriter(objectMapper);

    @Test
    void givenNullDelegate_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new ProblemDetailsAccessDeniedHandler(null, problemDetailsWriter));
    }

    @Test
    void givenNullProblemDetailsWriter_whenConstructing_thenNullPointerExceptionIsThrown() {
        AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
        assertThatNullPointerException()
                .isThrownBy(() -> new ProblemDetailsAccessDeniedHandler(delegate, null));
    }

    @Test
    void givenDelegateSetsStatusAndHeader_whenHandling_thenBothArePreservedAndProblemBodyReflectsTheStatus() throws Exception {
        AccessDeniedHandler delegate = (req, res, ex) -> {
            res.setStatus(403);
            res.setHeader("X-Custom", "value");
        };
        ProblemDetailsAccessDeniedHandler handler =
                new ProblemDetailsAccessDeniedHandler(delegate, problemDetailsWriter);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handle(request, response, new AccessDeniedException("denied"));

        assertThat(response.getStatus()).isEqualTo(403);
        assertThat(response.getHeader("X-Custom")).isEqualTo("value");

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(403);
        assertThat(body.get("detail").asString()).isEqualTo("Access is denied.");
        assertThat(response.getContentType()).isEqualTo("application/problem+json;charset=UTF-8");
    }

    @Test
    void givenDelegateRunsBeforeWritingTheBody_whenHandling_thenDelegateIsInvokedFirst() throws Exception {
        AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
        ProblemDetailsAccessDeniedHandler handler =
                new ProblemDetailsAccessDeniedHandler(delegate, problemDetailsWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AccessDeniedException exception = new AccessDeniedException("denied");

        handler.handle(request, response, exception);

        verify(delegate).handle(request, response, exception);
    }

    @Test
    void givenDelegateThrows_whenHandling_thenExceptionPropagatesAndProblemDetailsWriterIsNeverCalled() throws Exception {
        AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
        willThrow(new IOException("delegate failure"))
                .given(delegate).handle(any(), any(), any());
        ProblemDetailsAccessDeniedHandler handler =
                new ProblemDetailsAccessDeniedHandler(delegate, problemDetailsWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThatThrownBy(() -> handler.handle(request, response, new AccessDeniedException("denied")))
                .isInstanceOf(IOException.class)
                .hasMessage("delegate failure");

        assertThat(response.getContentAsString()).isEmpty();
    }

    @Test
    void givenResponseAlreadyCommittedByDelegate_whenHandling_thenProblemDetailsWriterDoesNotOverrideTheBody() throws Exception {
        AccessDeniedHandler delegate = (req, res, ex) -> {
            res.getWriter().write("delegate body");
            res.flushBuffer();
        };
        ProblemDetailsAccessDeniedHandler handler =
                new ProblemDetailsAccessDeniedHandler(delegate, problemDetailsWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handle(request, response, new AccessDeniedException("denied"));

        assertThat(response.getContentAsString()).isEqualTo("delegate body");
    }
}
