package com.trust.security.client.stepup;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class AcrStepUpAuthenticationSuccessHandlerTest {

    private static final Authentication AUTHENTICATION =
            UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of());

    @Test
    void givenNullDelegate_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new AcrStepUpAuthenticationSuccessHandler(null));
    }

    @Test
    void givenNoSession_whenHandlingSuccess_thenDelegateIsCalled() throws Exception {
        AuthenticationSuccessHandler delegate = mock(AuthenticationSuccessHandler.class);
        AcrStepUpAuthenticationSuccessHandler handler = new AcrStepUpAuthenticationSuccessHandler(delegate);
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, AUTHENTICATION);

        verify(delegate).onAuthenticationSuccess(request, response, AUTHENTICATION);
        assertThat(response.getRedirectedUrl()).isNull();
    }

    @Test
    void givenSessionWithoutReturnToAttribute_whenHandlingSuccess_thenDelegateIsCalled() throws Exception {
        AuthenticationSuccessHandler delegate = mock(AuthenticationSuccessHandler.class);
        AcrStepUpAuthenticationSuccessHandler handler = new AcrStepUpAuthenticationSuccessHandler(delegate);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, AUTHENTICATION);

        verify(delegate).onAuthenticationSuccess(request, response, AUTHENTICATION);
    }

    @Test
    void givenSessionWithReturnToAttribute_whenHandlingSuccess_thenRedirectsToTargetAndSkipsDelegate() throws Exception {
        AuthenticationSuccessHandler delegate = mock(AuthenticationSuccessHandler.class);
        AcrStepUpAuthenticationSuccessHandler handler = new AcrStepUpAuthenticationSuccessHandler(delegate);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.getSession(true).setAttribute(AcrStepUpController.STEP_UP_RETURN_TO, "/documents/42");
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(request, response, AUTHENTICATION);

        assertThat(response.getRedirectedUrl()).isEqualTo("/documents/42");
        verifyNoInteractions(delegate);
    }

    @Test
    void givenReturnToAttributeConsumed_whenHandlingSuccessAgainOnSameSession_thenNotReusedAndDelegateIsCalled() throws Exception {
        AuthenticationSuccessHandler delegate = mock(AuthenticationSuccessHandler.class);
        AcrStepUpAuthenticationSuccessHandler handler = new AcrStepUpAuthenticationSuccessHandler(delegate);
        MockHttpServletRequest firstRequest = new MockHttpServletRequest();
        firstRequest.getSession(true).setAttribute(AcrStepUpController.STEP_UP_RETURN_TO, "/documents/42");
        handler.onAuthenticationSuccess(firstRequest, new MockHttpServletResponse(), AUTHENTICATION);

        MockHttpServletRequest secondRequest = new MockHttpServletRequest();
        secondRequest.setSession(firstRequest.getSession(false));
        MockHttpServletResponse secondResponse = new MockHttpServletResponse();

        handler.onAuthenticationSuccess(secondRequest, secondResponse, AUTHENTICATION);

        assertThat(secondResponse.getRedirectedUrl()).isNull();
        verify(delegate).onAuthenticationSuccess(secondRequest, secondResponse, AUTHENTICATION);
    }
}
