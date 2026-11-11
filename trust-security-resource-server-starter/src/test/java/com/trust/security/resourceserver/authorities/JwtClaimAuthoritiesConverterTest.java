package com.trust.security.resourceserver.authorities;

import com.trust.security.core.role.AuthorityClaimMapping;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

/**
 * Verifies that {@link JwtClaimAuthoritiesConverter} applies the configured,
 * provider-agnostic {@link AuthorityClaimMapping} paths end-to-end against a
 * JWT. Test data deliberately uses neutral claim names ({@code
 * permissions.roles}, {@code application.{clientId}.roles}) rather than
 * Keycloak-shaped ones ({@code realm_access}/{@code resource_access}) to
 * demonstrate the converter is not coupled to any specific provider - it is
 * driven entirely by the configured mapping paths.
 */
class JwtClaimAuthoritiesConverterTest {

    private static Jwt jwtWithClaims(Map<String, Object> claims) {
        return Jwt.withTokenValue("token-value")
                .header("alg", "none")
                .issuedAt(Instant.EPOCH)
                .expiresAt(Instant.EPOCH.plusSeconds(3600))
                .claims(c -> c.putAll(claims))
                .build();
    }

    @Test
    void givenNullMapper_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new JwtClaimAuthoritiesConverter(null, "my-app"));
    }

    @Test
    void givenGlobalAndClientRoleMappingsForConfiguredClient_whenConvertingJwt_thenBothAreExtracted() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("permissions.roles", "ROLE_", null),
                new AuthorityClaimMapping("application.{clientId}.roles", "ROLE_", null)));
        JwtClaimAuthoritiesConverter converter = new JwtClaimAuthoritiesConverter(mapper, "my-app");

        Jwt jwt = jwtWithClaims(Map.of(
                "permissions", Map.of("roles", List.of("user")),
                "application", Map.of("my-app", Map.of("roles", List.of("editor")))));

        Collection<GrantedAuthority> authorities = converter.convert(jwt);

        assertThat(authorities).containsExactlyInAnyOrder(
                new SimpleGrantedAuthority("ROLE_user"),
                new SimpleGrantedAuthority("ROLE_editor"));
    }

    @Test
    void givenClientRoleMappingForAnotherClient_whenConvertingJwt_thenThoseRolesAreNotLeakedToTheCurrentClient() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("application.{clientId}.roles", "ROLE_", null)));
        JwtClaimAuthoritiesConverter converter = new JwtClaimAuthoritiesConverter(mapper, "my-app");

        Jwt jwt = jwtWithClaims(Map.of(
                "application", Map.of("other-app", Map.of("roles", List.of("editor")))));

        Collection<GrantedAuthority> authorities = converter.convert(jwt);

        assertThat(authorities).isEmpty();
    }

    @Test
    void givenNoMappingsConfigured_whenConvertingJwt_thenNoBusinessAuthorityIsExtracted() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of());
        JwtClaimAuthoritiesConverter converter = new JwtClaimAuthoritiesConverter(mapper, "my-app");

        Jwt jwt = jwtWithClaims(Map.of("permissions", Map.of("roles", List.of("user"))));

        Collection<GrantedAuthority> authorities = converter.convert(jwt);

        assertThat(authorities).isEmpty();
    }

    @Test
    void givenNullClientId_whenConvertingJwt_thenClientScopedMappingYieldsNoAuthorityWithoutError() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("application.{clientId}.roles", "ROLE_", null)));
        JwtClaimAuthoritiesConverter converter = new JwtClaimAuthoritiesConverter(mapper, null);

        Jwt jwt = jwtWithClaims(Map.of(
                "application", Map.of("my-app", Map.of("roles", List.of("editor")))));

        Collection<GrantedAuthority> authorities = converter.convert(jwt);

        assertThat(authorities).isEmpty();
    }
}
