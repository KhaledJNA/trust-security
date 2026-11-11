package com.trust.security.client.tenant;

import com.trust.web.problem.ProblemDetailsWriter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Objects;
import java.util.Optional;

/**
 * Intercepts only requests matching the configured tenant login
 * {@code request-pattern}, resolves a {@code registrationId} from them via
 * {@link TrustRegistrationIdResolver}, then redirects to Spring's own
 * {@code /oauth2/authorization/{registrationId}} - never building, resolving,
 * or redirecting to anything else itself. Every other request passes through
 * untouched, including {@code /oauth2/authorization/**} itself, which this
 * filter never matches by construction (see the startup guard in
 * {@link TenantLoginConfiguration} rejecting an overlapping
 * {@code request-pattern}).
 * <p>
 * A redirect (HTTP 302), not an internal forward: the target is always
 * {@code /oauth2/authorization/<a value validated at startup>}, so this can
 * never become an open redirect, and - unlike a forward - it does not depend
 * on {@code spring.security.filter.dispatcher-types} including {@code FORWARD}
 * (Spring Boot's default includes it, but an application could narrow it).
 * The original query string (e.g. {@code acr_values} for step-up) is
 * preserved, so {@link com.trust.security.client.stepup.AcrOAuth2AuthorizationRequestResolver} sees it
 * unchanged on the re-triggered request - no composition between the two
 * mechanisms is needed.
 * <p>
 * An unresolved tenant/host is rejected here directly (Problem Details, HTTP
 * {@link HttpStatus#NOT_FOUND}) rather than left to fall through to
 * {@code authorizeHttpRequests()}, which would otherwise send an
 * unauthenticated caller to Spring's own auto-generated multi-registration
 * login page - a confusing result for what is actually a configuration/input
 * error, not "please choose how to log in". Never reveals, in the response,
 * which hosts/tenants are actually configured.
 */
public final class TenantLoginRequestFilter extends OncePerRequestFilter {

    private static final String AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization/";

    private final RequestMatcher requestMatcher;
    private final TrustRegistrationIdResolver registrationIdResolver;
    private final ProblemDetailsWriter problemDetailsWriter;

    TenantLoginRequestFilter(
            String requestPattern,
            TrustRegistrationIdResolver registrationIdResolver,
            ProblemDetailsWriter problemDetailsWriter) {

        this.requestMatcher = PathPatternRequestMatcher.pathPattern(requestPattern);
        this.registrationIdResolver = Objects.requireNonNull(
                registrationIdResolver, "registrationIdResolver must not be null");
        this.problemDetailsWriter = Objects.requireNonNull(
                problemDetailsWriter, "problemDetailsWriter must not be null");
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        if (!requestMatcher.matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        Optional<String> registrationId = registrationIdResolver.resolve(request);

        if (registrationId.isEmpty()) {
            response.setStatus(HttpStatus.NOT_FOUND.value());
            problemDetailsWriter.write(request, response, "No login registration matches this request.");
            return;
        }

        response.sendRedirect(redirectUri(request, registrationId.get()));
    }

    private static String redirectUri(HttpServletRequest request, String registrationId) {
        String queryString = request.getQueryString();
        String uri = request.getContextPath() + AUTHORIZATION_REQUEST_BASE_URI + registrationId;
        return queryString == null ? uri : uri + "?" + queryString;
    }
}
