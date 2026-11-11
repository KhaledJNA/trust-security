package com.trust.security.web;

import com.trust.security.core.acr.AcrAuthorizationResult;
import com.trust.web.problem.ProblemDetailsWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.util.Objects;

/**
 * Turns a failed {@code @RequiresAcr} check into a step-up challenge
 * (RFC 9470): {@code 401} with
 * {@code WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="..."}
 * and a Problem Details body. Any other access denial goes to the delegate.
 */
public final class AcrStepUpAccessDeniedHandler
        implements AccessDeniedHandler {

    public static final String BEARER_ERROR_INSUFFICIENT_USER_AUTHENTICATION = "Bearer error=\"insufficient_user_authentication\"";
    public static final String ACR_VALUES = "acr_values=\"";
    public static final String STRONGER_AUTHENTICATION_IS_REQUIRED = "Stronger authentication is required.";
    private final AccessDeniedHandler delegate;
    private final ProblemDetailsWriter problemDetailsWriter;

    public AcrStepUpAccessDeniedHandler(
            AccessDeniedHandler delegate,
            ProblemDetailsWriter problemDetailsWriter) {

        this.delegate = Objects.requireNonNull(
                delegate,
                "delegate must not be null"
        );

        this.problemDetailsWriter = Objects.requireNonNull(
                problemDetailsWriter,
                "problemDetailsWriter must not be null"
        );
    }

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException)
            throws IOException, ServletException {

        String requiredAcr = requiredAcr(accessDeniedException);
        if (requiredAcr == null) {
            delegate.handle(request, response, accessDeniedException);
            return;
        }

        response.setStatus(HttpStatus.UNAUTHORIZED.value());
        response.setHeader(
                HttpHeaders.WWW_AUTHENTICATE,
                BEARER_ERROR_INSUFFICIENT_USER_AUTHENTICATION + ", "
                        + ACR_VALUES + quotedStringContent(requiredAcr) + "\""
        );
        problemDetailsWriter.write(request, response, STRONGER_AUTHENTICATION_IS_REQUIRED);
    }

    /** The ACR to ask for, or {@code null} when the denial is not an insufficient-ACR one. */
    private static @Nullable String requiredAcr(AccessDeniedException exception) {
        if (exception instanceof AuthorizationDeniedException denied
                && denied.getAuthorizationResult() instanceof AcrAuthorizationResult acrResult
                && !acrResult.isGranted()) {
            String requiredAcr = acrResult.requiredAcr();
            return requiredAcr == null || requiredAcr.isBlank() ? null : requiredAcr;
        }
        return null;
    }

    /**
     * Escapes the value for an RFC 9110 quoted-string: backslash and double
     * quote are escaped, control characters (CR/LF included) are dropped, so
     * the value can never break out of the header parameter.
     */
    static String quotedStringContent(String value) {
        StringBuilder escaped = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '"' || c == '\\') {
                escaped.append('\\').append(c);
            } else if (!Character.isISOControl(c)) {
                escaped.append(c);
            }
        }
        return escaped.toString();
    }
}
