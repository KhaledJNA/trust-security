package com.trust.security.web.audit;

import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioral tests for {@link AuthenticatedSubjectMdcFilter}.
 */
class AuthenticatedSubjectMdcFilterTest {

    private static final String MDC_KEY = "subject";

    private final AuthenticatedSubjectMdcFilter filter = new AuthenticatedSubjectMdcFilter();

    private static ClaimAccessor claims(Map<String, Object> values) {
        return () -> values;
    }

    @AfterEach
    void cleanUp() {
        MDC.clear();
        SecurityContextHolder.clearContext();
    }

    @Test
    void givenNoAuthentication_whenFilterExecutes_thenMdcSubjectIsNeverSetAndChainStillRuns() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(mdcDuringChain.get()).isNull();
        assertThat(MDC.get(MDC_KEY)).isNull();
    }

    @Test
    void givenUnauthenticatedAuthentication_whenFilterExecutes_thenMdcSubjectIsNotSet() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        claims(Map.of("sub", "user-1")), "credentials"));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(mdcDuringChain.get()).isNull();
    }

    @Test
    void givenPrincipalNotExposingClaims_whenFilterExecutes_thenMdcSubjectIsNotSet() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        "plain-string-principal", "credentials", List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(mdcDuringChain.get()).isNull();
    }

    @Test
    void givenClaimAccessorPrincipalWithSub_whenFilterExecutes_thenMdcSubjectIsAvailableDuringChain() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of("sub", "user-42")), "credentials", List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(mdcDuringChain.get()).isEqualTo("user-42");
    }

    @Test
    void givenSubClaimAbsent_whenFilterExecutes_thenMdcSubjectIsNotSet() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of("email", "user@example.com")), "credentials", List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(mdcDuringChain.get()).isNull();
    }

    @Test
    void givenSubClaimBlank_whenFilterExecutes_thenMdcSubjectIsNotSet() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of("sub", "   ")), "credentials", List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();
        FilterChain chain = (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY));

        filter.doFilter(request, response, chain);

        assertThat(mdcDuringChain.get()).isNull();
    }

    @Test
    void givenNormalCompletion_whenFilterFinishes_thenMdcSubjectIsRemoved() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of("sub", "user-42")), "credentials", List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> { };

        filter.doFilter(request, response, chain);

        assertThat(MDC.get(MDC_KEY)).isNull();
    }

    @Test
    void givenExceptionInChain_whenFilterExecutes_thenMdcSubjectIsStillRemovedAndExceptionPropagates() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of("sub", "user-42")), "credentials", List.of()));
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = (req, res) -> {
            throw new IllegalStateException("downstream failure");
        };

        assertThatThrownBy(() -> filter.doFilter(request, response, chain))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("downstream failure");

        assertThat(MDC.get(MDC_KEY)).isNull();
    }

    @Test
    void givenSubjectSetOnAPreviousRequest_whenANewUnauthenticatedRequestRuns_thenItDoesNotLeakTheOldSubject() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of("sub", "alice")), "credentials", List.of()));
        filter.doFilter(
                new MockHttpServletRequest("GET", "/orders"),
                new MockHttpServletResponse(),
                (req, res) -> { });

        SecurityContextHolder.clearContext();
        AtomicReference<String> mdcOnSecondRequest = new AtomicReference<>();
        filter.doFilter(
                new MockHttpServletRequest("GET", "/orders"),
                new MockHttpServletResponse(),
                (req, res) -> mdcOnSecondRequest.set(MDC.get(MDC_KEY)));

        assertThat(mdcOnSecondRequest.get()).isNull();
    }

    @Test
    void givenOpaqueTokenPrincipalWithSub_whenFilterExecutes_thenMdcSubjectIsSet() throws Exception {
        DefaultOAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(
                Map.of("sub", "user-opaque"), List.of());
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(principal, "token", List.of()));
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();

        filter.doFilter(new MockHttpServletRequest("GET", "/orders"), new MockHttpServletResponse(),
                (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY)));

        assertThat(mdcDuringChain.get()).isEqualTo("user-opaque");
    }

    @Test
    void givenAnonymousAuthentication_whenFilterExecutes_thenMdcSubjectIsNotSet() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken(
                "key", claims(Map.of("sub", "anonymous")), AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();

        filter.doFilter(new MockHttpServletRequest("GET", "/orders"), new MockHttpServletResponse(),
                (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY)));

        assertThat(mdcDuringChain.get()).isNull();
    }

    @Test
    void givenSubjectAlreadyInMdc_whenFilterFinishes_thenPreviousValueIsRestored() throws Exception {
        MDC.put(MDC_KEY, "outer");
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of("sub", "user-42")), "credentials", List.of()));
        AtomicReference<String> mdcDuringChain = new AtomicReference<>();

        filter.doFilter(new MockHttpServletRequest("GET", "/orders"), new MockHttpServletResponse(),
                (req, res) -> mdcDuringChain.set(MDC.get(MDC_KEY)));

        assertThat(mdcDuringChain.get()).isEqualTo("user-42");
        assertThat(MDC.get(MDC_KEY)).isEqualTo("outer");
    }
}
