package com.trust.security.web;

import com.trust.security.core.acr.AcrAuthorizationResult;
import com.trust.web.problem.ProblemDetailsWriter;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Behavioral tests for {@link AcrStepUpAccessDeniedHandler}.
 * <p>
 * Uses a real {@link ProblemDetailsWriter} (cheap, already tested in
 * trust-web-core) so the JSON body assertions exercise the actual writer
 * contract, not a mocked stand-in.
 */
class AcrStepUpAccessDeniedHandlerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ProblemDetailsWriter problemDetailsWriter = new ProblemDetailsWriter(objectMapper);

    @Test
    void givenNullDelegate_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new AcrStepUpAccessDeniedHandler(null, problemDetailsWriter));
    }

    @Test
    void givenNullProblemDetailsWriter_whenConstructing_thenNullPointerExceptionIsThrown() {
        AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
        assertThatNullPointerException()
                .isThrownBy(() -> new AcrStepUpAccessDeniedHandler(delegate, null));
    }

    @Test
    void givenInsufficientAcr_whenHandling_thenRespondsWithUnauthorizedAndWwwAuthenticateAndProblemBody() throws Exception {
        AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
        AcrStepUpAccessDeniedHandler handler = new AcrStepUpAccessDeniedHandler(delegate, problemDetailsWriter);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthorizationDeniedException exception = new AuthorizationDeniedException(
                "denied", new AcrAuthorizationResult(false, "urn:acr:mfa"));

        handler.handle(request, response, exception);

        assertThat(response.getStatus()).isEqualTo(401);
        assertThat(response.getHeader("WWW-Authenticate"))
                .isEqualTo("Bearer error=\"insufficient_user_authentication\", acr_values=\"urn:acr:mfa\"");

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(401);
        assertThat(body.get("detail").asString()).isEqualTo("Stronger authentication is required.");

        verifyNoInteractions(delegate);
    }

    /**
     * There is no test for an {@code AuthorizationDeniedException} wrapping a
     * "granted" {@code AcrAuthorizationResult}: Spring Security's own
     * {@code AuthorizationDeniedException} constructor asserts the wrapped
     * result is never granted ("Granted authorization results are not
     * supported"), so this state is structurally unreachable - the handler's
     * own {@code !acrResult.isGranted()} check is defensive redundancy, not
     * a reachable branch.
     */
    @Test
    void givenAuthorizationDeniedExceptionWithNonAcrResult_whenHandling_thenDelegatesToStandardHandler() throws Exception {
        AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
        AcrStepUpAccessDeniedHandler handler = new AcrStepUpAccessDeniedHandler(delegate, problemDetailsWriter);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthorizationDeniedException exception = new AuthorizationDeniedException(
                "denied", new AuthorizationDecision(false));

        handler.handle(request, response, exception);

        verify(delegate).handle(request, response, exception);
        assertThat(response.getStatus()).isNotEqualTo(401);
    }

    @Test
    void givenPlainAccessDeniedException_whenHandling_thenDelegatesToStandardHandlerWithoutAcrHeaders() throws Exception {
        AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
        AcrStepUpAccessDeniedHandler handler = new AcrStepUpAccessDeniedHandler(delegate, problemDetailsWriter);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AccessDeniedException exception = new AccessDeniedException("plain denial");

        handler.handle(request, response, exception);

        verify(delegate).handle(request, response, exception);
        assertThat(response.getHeader("WWW-Authenticate")).isNull();
    }

    @Test
    void givenRequiredAcrWithQuotesAndLineBreaks_whenHandling_thenHeaderValueIsEscaped() throws Exception {
        AcrStepUpAccessDeniedHandler handler =
                new AcrStepUpAccessDeniedHandler(mock(AccessDeniedHandler.class), problemDetailsWriter);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.handle(new MockHttpServletRequest("GET", "/documents/42"), response,
                new AuthorizationDeniedException("denied",
                        new AcrAuthorizationResult(false, "gold\", x=\"y\r\nSet-Cookie: a=b")));

        assertThat(response.getHeader("WWW-Authenticate")).isEqualTo(
                "Bearer error=\"insufficient_user_authentication\", acr_values=\"gold\\\", x=\\\"ySet-Cookie: a=b\"");
    }

    @Test
    void givenDeniedAcrResultWithoutRequiredAcr_whenHandling_thenDelegatesInsteadOfAskingForNull() throws Exception {
        AccessDeniedHandler delegate = mock(AccessDeniedHandler.class);
        AcrStepUpAccessDeniedHandler handler = new AcrStepUpAccessDeniedHandler(delegate, problemDetailsWriter);
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AuthorizationDeniedException exception =
                new AuthorizationDeniedException("denied", new AcrAuthorizationResult(false, null));

        handler.handle(request, response, exception);

        verify(delegate).handle(request, response, exception);
        assertThat(response.getHeader("WWW-Authenticate")).isNull();
    }
}
