package com.trust.security.core.user;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

class SecurityContextCurrentAuthoritiesProviderTest {

    private final SecurityContextCurrentAuthoritiesProvider provider =
            new SecurityContextCurrentAuthoritiesProvider();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void givenNoAuthenticationInSecurityContext_whenGettingAuthorities_thenResultIsEmpty() {
        Set<String> authorities = provider.getAuthorities();

        assertThat(authorities).isEmpty();
    }

    @Test
    void givenUnauthenticatedAuthentication_whenGettingAuthorities_thenResultIsEmpty() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.unauthenticated("user-1", "credentials"));

        Set<String> authorities = provider.getAuthorities();

        assertThat(authorities).isEmpty();
    }

    @Test
    void givenAuthenticatedUserWithAuthorities_whenGettingAuthorities_thenAllAuthorityNamesAreExposed() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        "user-1",
                        "credentials",
                        List.of(new SimpleGrantedAuthority("ROLE_admin"),
                                new SimpleGrantedAuthority("ROLE_editor"))));

        Set<String> authorities = provider.getAuthorities();

        assertThat(authorities).containsExactlyInAnyOrder("ROLE_admin", "ROLE_editor");
    }

    @Test
    void givenAuthenticatedUserWithAuthorities_whenGettingAuthorities_thenReturnedSetIsUnmodifiable() {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated(
                        "user-1", "credentials",
                        List.of(new SimpleGrantedAuthority("ROLE_admin"))));

        Set<String> authorities = provider.getAuthorities();

        assertThatExceptionOfType(UnsupportedOperationException.class)
                .isThrownBy(() -> authorities.add("ROLE_hacker"));
    }

    @Test
    void givenAnonymousAuthentication_whenGettingAuthorities_thenRoleAnonymousIsNotReturned() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        assertThat(new SecurityContextCurrentAuthoritiesProvider().getAuthorities()).isEmpty();
    }
}
