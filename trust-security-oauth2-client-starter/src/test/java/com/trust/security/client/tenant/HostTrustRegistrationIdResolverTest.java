package com.trust.security.client.tenant;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class HostTrustRegistrationIdResolverTest {

    private static final Map<String, String> MAPPINGS = Map.of(
            "acme.application.fr", "keycloak-acme",
            "globex.application.fr", "keycloak-globex");

    @Test
    void givenKnownHost_whenResolving_thenRegistrationIdIsReturned() {
        HostTrustRegistrationIdResolver resolver = new HostTrustRegistrationIdResolver(MAPPINGS);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("acme.application.fr");

        assertThat(resolver.resolve(request)).contains("keycloak-acme");
    }

    @Test
    void givenUnknownHost_whenResolving_thenEmptyIsReturned() {
        HostTrustRegistrationIdResolver resolver = new HostTrustRegistrationIdResolver(MAPPINGS);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("unknown.application.fr");

        assertThat(resolver.resolve(request)).isEmpty();
    }

    @Test
    void givenHostWithDifferentCase_whenResolving_thenStillMatches() {
        HostTrustRegistrationIdResolver resolver = new HostTrustRegistrationIdResolver(MAPPINGS);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("ACME.application.fr");

        assertThat(resolver.resolve(request)).contains("keycloak-acme");
    }

    @Test
    void givenMappingWithDifferentCase_whenResolving_thenStillMatches() {
        HostTrustRegistrationIdResolver resolver =
                new HostTrustRegistrationIdResolver(Map.of("Acme.Application.Fr", "keycloak-acme"));
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("acme.application.fr");

        assertThat(resolver.resolve(request)).contains("keycloak-acme");
    }

    @Test
    void givenServerNameWithPort_whenResolving_thenPortNeverAffectsResolution() {
        // MockHttpServletRequest.getServerName() never includes the port -
        // same servlet-container contract this resolver relies on in production.
        HostTrustRegistrationIdResolver resolver = new HostTrustRegistrationIdResolver(MAPPINGS);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setServerName("acme.application.fr");
        request.setServerPort(8443);

        Optional<String> resolved = resolver.resolve(request);

        assertThat(resolved).contains("keycloak-acme");
    }
}
