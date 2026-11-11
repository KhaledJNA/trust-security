package com.trust.security.resourceserver.authorities;

import com.trust.security.core.role.AuthorityClaimMapping;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that authorities are composed - never replaced - as on the JWT
 * side: an introspection response's native authorities
 * (e.g. {@code SCOPE_*}, already computed by the delegate) and Trust's own
 * {@code trust.security.authorities.mappings}-driven authorities must both
 * survive.
 */
class TrustOpaqueTokenIntrospectorTest {

    @Test
    void whenIntrospecting_thenDelegateAuthoritiesAndMappedAuthoritiesAreBothPresent() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("realm_access.roles", "ROLE_", null)));

        OpaqueTokenIntrospector delegate = token -> new DefaultOAuth2AuthenticatedPrincipal(
                "user-1",
                Map.of("realm_access", Map.of("roles", List.of("admin", "operator"))),
                List.of(new SimpleGrantedAuthority("SCOPE_documents.read")));

        TrustOpaqueTokenIntrospector introspector =
                new TrustOpaqueTokenIntrospector(delegate, mapper, "sample-downstream-api");

        OAuth2AuthenticatedPrincipal principal = introspector.introspect("opaque-token-value");

        assertThat(principal.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("SCOPE_documents.read", "ROLE_admin", "ROLE_operator");
    }

    @Test
    void whenIntrospecting_thenNameAndAttributesArePreservedFromDelegate() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of());
        Map<String, Object> attributes = Map.of("sub", "user-1", "active", true);

        OpaqueTokenIntrospector delegate = token ->
                new DefaultOAuth2AuthenticatedPrincipal("user-1", attributes, List.of());

        TrustOpaqueTokenIntrospector introspector =
                new TrustOpaqueTokenIntrospector(delegate, mapper, null);

        OAuth2AuthenticatedPrincipal principal = introspector.introspect("opaque-token-value");

        assertThat(principal.getName()).isEqualTo("user-1");
        assertThat(principal.getAttributes()).isEqualTo(attributes);
    }

    @Test
    void givenClientIdMappingPlaceholder_whenIntrospecting_thenItIsSubstituted() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("resource_access.{clientId}.roles", "ROLE_", null)));

        OpaqueTokenIntrospector delegate = token -> new DefaultOAuth2AuthenticatedPrincipal(
                "user-1",
                Map.of("resource_access", Map.of("sample-downstream-api", Map.of("roles", List.of("manager")))),
                List.of());

        TrustOpaqueTokenIntrospector introspector =
                new TrustOpaqueTokenIntrospector(delegate, mapper, "sample-downstream-api");

        OAuth2AuthenticatedPrincipal principal = introspector.introspect("opaque-token-value");

        assertThat(principal.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_manager");
    }
}
