package com.trust.security.core.acr;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClaimAccessor;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class AcrAuthorizationTest {

    private final AcrAuthorization acrAuthorization = new AcrAuthorization();

    private static ClaimAccessor claims(Map<String, Object> values) {
        return () -> values;
    }

    @Test
    void givenNullAuthentication_whenCheckingAcr_thenAccessIsDenied() {
        boolean result = acrAuthorization.hasAcr(null, "urn:acr:mfa");

        assertThat(result).isFalse();
    }

    @Test
    void givenUnauthenticatedAuthentication_whenCheckingAcr_thenAccessIsDenied() {
        Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(
                claims(Map.of("acr", "urn:acr:mfa")), "credentials");

        boolean result = acrAuthorization.hasAcr(authentication, "urn:acr:mfa");

        assertThat(result).isFalse();
    }

    @Test
    void givenAuthenticatedPrincipalNotExposingClaims_whenCheckingAcr_thenAccessIsDenied() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                "plain-string-principal", "credentials", java.util.List.of());

        boolean result = acrAuthorization.hasAcr(authentication, "urn:acr:mfa");

        assertThat(result).isFalse();
    }

    @Test
    void givenAuthenticatedPrincipalWithMatchingAcrClaim_whenCheckingAcr_thenAccessIsGranted() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                claims(Map.of("acr", "urn:acr:mfa")), "credentials", java.util.List.of());

        boolean result = acrAuthorization.hasAcr(authentication, "urn:acr:mfa");

        assertThat(result).isTrue();
    }

    @Test
    void givenAuthenticatedPrincipalWithDifferentAcrClaim_whenCheckingAcr_thenAccessIsDenied() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                claims(Map.of("acr", "urn:acr:basic")), "credentials", java.util.List.of());

        boolean result = acrAuthorization.hasAcr(authentication, "urn:acr:mfa");

        assertThat(result).isFalse();
    }

    @Test
    void givenAuthenticatedPrincipalWithoutAcrClaim_whenCheckingAcr_thenAccessIsDenied() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                claims(Map.of("sub", "user-1")), "credentials", java.util.List.of());

        boolean result = acrAuthorization.hasAcr(authentication, "urn:acr:mfa");

        assertThat(result).isFalse();
    }

    /**
     * expectedAcr represents a programming/configuration error (e.g. a
     * misconfigured {@code @RequiresAcr}) and must never be null - this is a
     * deliberate fail-fast contract, not an accidental NPE from the comparison
     * logic below.
     */
    @Test
    void givenNullExpectedAcr_whenCheckingAcr_thenNullPointerExceptionIsThrownExplicitly() {
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(
                claims(Map.of("acr", "urn:acr:mfa")), "credentials", java.util.List.of());

        assertThatNullPointerException()
                .isThrownBy(() -> acrAuthorization.hasAcr(authentication, null))
                .withMessage("expectedAcr must not be null");
    }

    @Test
    void givenNullExpectedAcrAndNullAuthentication_whenCheckingAcr_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> acrAuthorization.hasAcr(null, null))
                .withMessage("expectedAcr must not be null");
    }

    @Test
    void givenOpaqueTokenPrincipalWithMatchingAcr_whenCheckingAcr_thenAccessIsGranted() {
        DefaultOAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(
                "user-1", Map.of("acr", "urn:acr:mfa"), AuthorityUtils.NO_AUTHORITIES);
        Authentication authentication = UsernamePasswordAuthenticationToken.authenticated(principal, null, List.of());

        assertThat(acrAuthorization.hasAcr(authentication, "urn:acr:mfa")).isTrue();
    }

    @Test
    void givenAnonymousAuthentication_whenCheckingAcr_thenAccessIsDenied() {
        Authentication anonymous = new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        assertThat(acrAuthorization.hasAcr(anonymous, "urn:acr:mfa")).isFalse();
    }
}
