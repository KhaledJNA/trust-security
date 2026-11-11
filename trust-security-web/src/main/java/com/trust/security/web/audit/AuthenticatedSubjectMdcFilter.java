package com.trust.security.web.audit;

import com.trust.security.core.user.PrincipalClaims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Puts the caller's {@code sub} claim in the logging MDC under
 * {@value #MDC_KEY} for the rest of the request.
 * <p>
 * Works for every token format {@link PrincipalClaims} understands: JWT,
 * OIDC login and opaque-token introspection. Anonymous or unauthenticated
 * requests get no entry. A value already in the MDC (set by an outer filter)
 * is put back when the request ends, rather than removed.
 * <p>
 * Must run after the filter that populates the security context.
 */
public final class AuthenticatedSubjectMdcFilter extends OncePerRequestFilter {

    public static final String MDC_KEY = "subject";

    private static final String SUBJECT_CLAIM = "sub";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String previous = MDC.get(MDC_KEY);
        try {
            PrincipalClaims.of(SecurityContextHolder.getContext().getAuthentication())
                    .map(claims -> claims.getAsString(SUBJECT_CLAIM))
                    .filter(subject -> !subject.isBlank())
                    .ifPresent(subject -> MDC.put(MDC_KEY, subject));

            filterChain.doFilter(request, response);
        } finally {
            if (previous != null) {
                MDC.put(MDC_KEY, previous);
            } else {
                MDC.remove(MDC_KEY);
            }
        }
    }
}
