package com.trust.security.client.tenant;

import com.trust.web.problem.ProblemDetailsWriter;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.ObjectMapper;

import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Pure servlet-level tests - no Spring context, no {@code SecurityFilterChain} -
 * for exactly what this filter itself decides: whether to intervene at all,
 * and how it redirects or rejects when it does.
 */
class TenantLoginRequestFilterTest {

    private static final ProblemDetailsWriter PROBLEM_DETAILS_WRITER = new ProblemDetailsWriter(new ObjectMapper());

    private static TenantLoginRequestFilter filter(TrustRegistrationIdResolver resolver) {
        return new TenantLoginRequestFilter("/sso/login/{tenant}", resolver, PROBLEM_DETAILS_WRITER);
    }

    @Test
    void givenRequestNotMatchingPattern_whenFiltering_thenChainContinuesAndResolverIsNeverCalled() throws Exception {
        AtomicBoolean resolverCalled = new AtomicBoolean(false);
        TrustRegistrationIdResolver resolver = request -> {
            resolverCalled.set(true);
            return Optional.of("keycloak-acme");
        };
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/unrelated/path");
        request.setRequestURI("/unrelated/path");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(resolver).doFilter(request, response, (req, res) -> chainCalled.set(true));

        assertThat(chainCalled).isTrue();
        assertThat(resolverCalled).isFalse();
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void givenMatchingRequestWithResolvedTenant_whenFiltering_thenRedirectsToOAuth2AuthorizationEndpoint()
            throws Exception {
        TrustRegistrationIdResolver resolver = request -> Optional.of("keycloak-acme");
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/sso/login/acme");
        request.setRequestURI("/sso/login/acme");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(resolver).doFilter(request, response, (req, res) -> chainCalled.set(true));

        assertThat(chainCalled).isFalse();
        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo("/oauth2/authorization/keycloak-acme");
    }

    @Test
    void givenMatchingRequestWithQueryString_whenFiltering_thenQueryStringIsPreservedOnRedirect() throws Exception {
        TrustRegistrationIdResolver resolver = request -> Optional.of("keycloak-acme");

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/sso/login/acme");
        request.setRequestURI("/sso/login/acme");
        request.setQueryString("acr_values=urn:acr:mfa");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(resolver).doFilter(request, response, (req, res) -> { });

        assertThat(response.getRedirectedUrl())
                .isEqualTo("/oauth2/authorization/keycloak-acme?acr_values=urn:acr:mfa");
    }

    @Test
    void givenMatchingRequestWithUnresolvedTenant_whenFiltering_thenRejectedWithProblemDetailsNotFound()
            throws Exception {
        TrustRegistrationIdResolver resolver = request -> Optional.empty();
        AtomicBoolean chainCalled = new AtomicBoolean(false);

        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/sso/login/unknown");
        request.setRequestURI("/sso/login/unknown");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter(resolver).doFilter(request, response, (req, res) -> chainCalled.set(true));

        assertThat(chainCalled).isFalse();
        assertThat(response.getStatus()).isEqualTo(404);
        assertThat(response.getContentType()).startsWith("application/problem+json");
        // "detail" is always this fixed, generic string - it never echoes the
        // unresolved value or enumerates which hosts/tenants ARE configured.
        // ("instance" does echo the request's own path, per RFC 9457
        // standard practice - not a leak of anything the caller didn't
        // already know themselves.)
        assertThat(response.getContentAsString()).contains("\"detail\":\"No login registration matches this request.\"");
    }
}
