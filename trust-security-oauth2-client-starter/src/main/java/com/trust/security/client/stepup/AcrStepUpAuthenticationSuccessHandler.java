package com.trust.security.client.stepup;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.DefaultRedirectStrategy;

import java.io.IOException;
import java.util.Objects;

public final class AcrStepUpAuthenticationSuccessHandler
        implements AuthenticationSuccessHandler {

    private final AuthenticationSuccessHandler delegate;
    private final RedirectStrategy redirectStrategy =
            new DefaultRedirectStrategy();

    public AcrStepUpAuthenticationSuccessHandler(
            AuthenticationSuccessHandler delegate) {

        this.delegate = Objects.requireNonNull(
                delegate,
                "delegate must not be null"
        );
    }

    @Override
    public void onAuthenticationSuccess(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication)
            throws IOException, ServletException {

        HttpSession session = request.getSession(false);

        if (session != null) {
            Object returnTo = session.getAttribute(
                    AcrStepUpController.STEP_UP_RETURN_TO
            );

            if (returnTo instanceof String targetUrl) {
                session.removeAttribute(
                        AcrStepUpController.STEP_UP_RETURN_TO
                );

                redirectStrategy.sendRedirect(
                        request,
                        response,
                        targetUrl
                );
                return;
            }
        }

        delegate.onAuthenticationSuccess(
                request,
                response,
                authentication
        );
    }
}