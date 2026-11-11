package com.trust.security.client.tenant;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PathVariableTrustRegistrationIdResolverTest {

    private static final Map<String, String> MAPPINGS = Map.of(
            "acme", "keycloak-acme",
            "globex", "keycloak-globex");

    private static PathVariableTrustRegistrationIdResolver resolver() {
        return new PathVariableTrustRegistrationIdResolver("/sso/login/{tenant}", "tenant", MAPPINGS);
    }

    private static MockHttpServletRequest requestTo(String uri) {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", uri);
        request.setRequestURI(uri);
        return request;
    }

    @Test
    void givenKnownTenantInPath_whenResolving_thenRegistrationIdIsReturned() {
        assertThat(resolver().resolve(requestTo("/sso/login/acme"))).contains("keycloak-acme");
    }

    @Test
    void givenUnknownTenantInPath_whenResolving_thenEmptyIsReturned() {
        assertThat(resolver().resolve(requestTo("/sso/login/unknown"))).isEmpty();
    }

    @Test
    void givenNonMatchingPath_whenResolving_thenEmptyIsReturnedWithoutLookingAtMappings() {
        assertThat(resolver().resolve(requestTo("/unrelated/path"))).isEmpty();
    }
}
