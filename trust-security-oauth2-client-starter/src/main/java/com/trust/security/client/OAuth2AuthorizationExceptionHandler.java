package com.trust.security.client;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class OAuth2AuthorizationExceptionHandler {

    public static final String INVALID_GRANT = "invalid_grant";
    private final SecurityContextLogoutHandler logoutHandler =
            new SecurityContextLogoutHandler();

    @ExceptionHandler(OAuth2AuthorizationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public void handle(
            OAuth2AuthorizationException exception,
            HttpServletRequest request,
            HttpServletResponse response) {

        if (!INVALID_GRANT.equals(exception.getError().getErrorCode())) {
            throw exception;
        }

        Authentication authentication =
                SecurityContextHolder.getContext().getAuthentication();

        logoutHandler.logout(request, response, authentication);
    }
}