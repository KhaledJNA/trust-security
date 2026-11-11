package com.trust.security.client;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioral tests for {@link OAuth2AuthorizationExceptionHandler}.
 * <p>
 * The class internally builds its own {@link org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler}
 * (not injected), so its effect is verified through the handler's real,
 * observable side effects - the security context being cleared and the HTTP
 * session invalidated - rather than through a mock. The {@code @ResponseStatus(UNAUTHORIZED)}
 * annotation is Spring MVC's own exception-resolution machinery, applied
 * only when Spring actually dispatches through {@code @ExceptionHandler};
 * it is not exercised by calling this method directly and is not this
 * starter's own logic to test.
 */
class OAuth2AuthorizationExceptionHandlerTest {

    private final OAuth2AuthorizationExceptionHandler handler = new OAuth2AuthorizationExceptionHandler();

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void givenInvalidGrantError_whenHandling_thenSecurityContextIsClearedAndSessionIsInvalidated() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();
        OAuth2AuthorizationException exception =
                new OAuth2AuthorizationException(new OAuth2Error("invalid_grant"));

        handler.handle(exception, request, response);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
        assertThat(session.isInvalid()).isTrue();
    }

    @Test
    void givenOtherAuthorizationError_whenHandling_thenTheSameExceptionIsRethrownWithoutLoggingOut() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpSession session = new MockHttpSession();
        request.setSession(session);
        MockHttpServletResponse response = new MockHttpServletResponse();
        OAuth2AuthorizationException exception =
                new OAuth2AuthorizationException(new OAuth2Error("invalid_request"));

        assertThatThrownBy(() -> handler.handle(exception, request, response))
                .isSameAs(exception);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
        assertThat(session.isInvalid()).isFalse();
    }

    @Test
    void givenInvalidGrantErrorWithNoAuthenticationInContext_whenHandling_thenNoExceptionIsThrown() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        OAuth2AuthorizationException exception =
                new OAuth2AuthorizationException(new OAuth2Error("invalid_grant"));

        handler.handle(exception, request, response);

        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
