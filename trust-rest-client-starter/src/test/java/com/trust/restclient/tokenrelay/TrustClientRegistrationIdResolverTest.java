package com.trust.restclient.tokenrelay;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.ClientAttributes;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.net.URI;
import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The three-case resolution order: request attribute, then the BFF
 * principal's own registration, then abstain.
 */
class TrustClientRegistrationIdResolverTest {

    private final TrustClientRegistrationIdResolver resolver = new TrustClientRegistrationIdResolver();

    @AfterEach
    void clearSecurityContext() {
        SecurityContextHolder.clearContext();
    }

    private static MockClientHttpRequest requestWithAttribute(String registrationId) {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/x"));
        if (registrationId != null) {
            ClientAttributes.clientRegistrationId(registrationId).accept(request.getAttributes());
        }
        return request;
    }

    @Test
    void givenTheRequestAttributeIsPresent_whenResolving_thenItWinsRegardlessOfAuthentication() {
        SecurityContextHolder.getContext().setAuthentication(bffAuthentication("bff-registration"));

        String resolved = resolver.resolve(requestWithAttribute("declared-registration"));

        assertThat(resolved).isEqualTo("declared-registration");
    }

    @Test
    void givenNoAttributeAndABffPrincipal_whenResolving_thenItReturnsTheRegistrationTheUserAuthenticatedWith() {
        SecurityContextHolder.getContext().setAuthentication(bffAuthentication("keycloak-bff"));

        String resolved = resolver.resolve(requestWithAttribute(null));

        assertThat(resolved).isEqualTo("keycloak-bff");
    }

    @Test
    void givenNoAttributeAndAResourceServerPrincipal_whenResolving_thenItAbstains() {
        Jwt jwt = Jwt.withTokenValue("token").header("alg", "none").claim("sub", "user-1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));

        String resolved = resolver.resolve(requestWithAttribute(null));

        assertThat(resolved).isNull();
    }

    @Test
    void givenNoAttributeAndAnonymousAuthentication_whenResolving_thenItAbstains() {
        SecurityContextHolder.getContext().setAuthentication(new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS")));

        String resolved = resolver.resolve(requestWithAttribute(null));

        assertThat(resolved).isNull();
    }

    @Test
    void givenNoAttributeAndNoAuthenticationAtAll_whenResolving_thenItAbstains() {
        String resolved = resolver.resolve(requestWithAttribute(null));

        assertThat(resolved).isNull();
    }

    private static OAuth2AuthenticationToken bffAuthentication(String registrationId) {
        DefaultOidcUser oidcUser = new DefaultOidcUser(
                AuthorityUtils.createAuthorityList("ROLE_USER"),
                new OidcIdToken("id-token-value", Instant.now(), Instant.now().plusSeconds(3600),
                        Map.of("sub", "user-1")));
        return new OAuth2AuthenticationToken(oidcUser, oidcUser.getAuthorities(), registrationId);
    }
}
