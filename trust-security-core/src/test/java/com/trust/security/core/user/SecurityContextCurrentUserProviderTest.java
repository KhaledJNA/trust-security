package com.trust.security.core.user;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.ClaimAccessor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityContextCurrentUserProviderTest {

    private final SecurityContextCurrentUserProvider provider = new SecurityContextCurrentUserProvider();

    private static ClaimAccessor claims(Map<String, Object> values) {
        return () -> values;
    }

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void givenNoAuthenticationInSecurityContext_whenGettingCurrentUser_thenResultIsEmpty() {
        Optional<AuthenticatedUser> currentUser = provider.getCurrentUser();

        assertThat(currentUser).isEmpty();
    }

    @Test
    void givenUnauthenticatedAuthentication_whenGettingCurrentUser_thenResultIsEmpty() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.unauthenticated(
                        claims(Map.of("sub", "user-1")), "credentials"));

        Optional<AuthenticatedUser> currentUser = provider.getCurrentUser();

        assertThat(currentUser).isEmpty();
    }

    @Test
    void givenAuthenticatedPrincipalNotExposingClaims_whenGettingCurrentUser_thenResultIsEmpty() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        "plain-string-principal", "credentials", List.of()));

        Optional<AuthenticatedUser> currentUser = provider.getCurrentUser();

        assertThat(currentUser).isEmpty();
    }

    @Test
    void givenAuthenticatedClaimAccessorPrincipal_whenGettingCurrentUser_thenClaimsAreMappedToAuthenticatedUser() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of(
                                "sub", "user-1",
                                "preferred_username", "jdoe",
                                "email", "jdoe@example.com")),
                        "credentials",
                        List.of()));

        Optional<AuthenticatedUser> currentUser = provider.getCurrentUser();

        assertThat(currentUser).contains(
                new AuthenticatedUser("user-1", "jdoe", "jdoe@example.com"));
    }

    @Test
    void givenAuthenticatedClaimAccessorPrincipalMissingOptionalClaims_whenGettingCurrentUser_thenMissingClaimsAreNull() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        claims(Map.of("sub", "user-1")),
                        "credentials",
                        List.of()));

        Optional<AuthenticatedUser> currentUser = provider.getCurrentUser();

        assertThat(currentUser).contains(new AuthenticatedUser("user-1", null, null));
    }

    @Test
    void givenOpaqueTokenPrincipal_whenGettingCurrentUser_thenAttributesAreMapped() {
        DefaultOAuth2AuthenticatedPrincipal principal = new DefaultOAuth2AuthenticatedPrincipal(
                "user-1", Map.of("sub", "user-1", "preferred_username", "jdoe"), AuthorityUtils.NO_AUTHORITIES);
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(principal, null, List.of()));

        assertThat(new SecurityContextCurrentUserProvider().getCurrentUser())
                .contains(new AuthenticatedUser("user-1", "jdoe", null));
    }

    @Test
    void givenPrincipalWithoutSubClaim_whenGettingCurrentUser_thenResultIsEmpty() {
        ClaimAccessor claims = () -> Map.of("preferred_username", "jdoe");
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(claims, null, List.of()));

        assertThat(new SecurityContextCurrentUserProvider().getCurrentUser()).isEmpty();
    }

    @Test
    void givenAnonymousAuthentication_whenGettingCurrentUser_thenResultIsEmpty() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        assertThat(new SecurityContextCurrentUserProvider().getCurrentUser()).isEmpty();
    }
}
