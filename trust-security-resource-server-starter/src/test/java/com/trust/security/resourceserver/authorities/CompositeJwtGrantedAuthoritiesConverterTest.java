package com.trust.security.resourceserver.authorities;

import com.trust.security.core.role.AuthorityClaimMapping;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

/**
 * Verifies that {@link CompositeJwtGrantedAuthoritiesConverter} composes
 * Spring Security's default {@link JwtGrantedAuthoritiesConverter} (standard
 * {@code SCOPE_*} authorities) with {@link JwtClaimAuthoritiesConverter}
 * (Trust's configuration-driven mapping) rather than one replacing the
 * other: a plain {@code scope} claim must still produce its authority when
 * Trust's mapping is configured.
 */
class CompositeJwtGrantedAuthoritiesConverterTest {

    private static Jwt jwtWithClaims(Map<String, Object> claims) {
        return Jwt.withTokenValue("token-value")
                .header("alg", "none")
                .issuedAt(Instant.EPOCH)
                .expiresAt(Instant.EPOCH.plusSeconds(3600))
                .claims(c -> c.putAll(claims))
                .build();
    }

    @Test
    void givenNullFirstConverter_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new CompositeJwtGrantedAuthoritiesConverter(
                        null, new JwtClaimAuthoritiesConverter(new ClaimAuthoritiesMapper(List.of()), "my-app")));
    }

    @Test
    void givenNullSecondConverter_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new CompositeJwtGrantedAuthoritiesConverter(
                        new JwtGrantedAuthoritiesConverter(), null));
    }

    @Test
    void givenJwtWithScopeClaimAndNoTrustMappingsConfigured_whenConverting_thenNativeScopeAuthoritiesArePreserved() {
        CompositeJwtGrantedAuthoritiesConverter converter = new CompositeJwtGrantedAuthoritiesConverter(
                new JwtGrantedAuthoritiesConverter(),
                new JwtClaimAuthoritiesConverter(new ClaimAuthoritiesMapper(List.of()), "my-app"));

        Jwt jwt = jwtWithClaims(Map.of("scope", "documents.read documents.write"));

        Collection<GrantedAuthority> authorities = converter.convert(jwt);

        assertThat(authorities).containsExactlyInAnyOrder(
                new SimpleGrantedAuthority("SCOPE_documents.read"),
                new SimpleGrantedAuthority("SCOPE_documents.write"));
    }

    @Test
    void givenJwtWithScopeAndRealmRolesAndTrustMappingsConfigured_whenConverting_thenTheUnionIsProducedWithoutDuplicates() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("realm_access.roles", "ROLE_", null)));
        CompositeJwtGrantedAuthoritiesConverter converter = new CompositeJwtGrantedAuthoritiesConverter(
                new JwtGrantedAuthoritiesConverter(),
                new JwtClaimAuthoritiesConverter(mapper, "my-app"));

        Jwt jwt = jwtWithClaims(Map.of(
                "scope", "documents.read",
                "realm_access", Map.of("roles", List.of("user", "auditor"))));

        Collection<GrantedAuthority> authorities = converter.convert(jwt);

        assertThat(authorities).containsExactlyInAnyOrder(
                new SimpleGrantedAuthority("SCOPE_documents.read"),
                new SimpleGrantedAuthority("ROLE_user"),
                new SimpleGrantedAuthority("ROLE_auditor"));
    }

    @Test
    void givenBothConvertersProduceTheSameAuthority_whenConverting_thenItAppearsOnlyOnce() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("scope", "SCOPE_", " ")));
        CompositeJwtGrantedAuthoritiesConverter converter = new CompositeJwtGrantedAuthoritiesConverter(
                new JwtGrantedAuthoritiesConverter(),
                new JwtClaimAuthoritiesConverter(mapper, "my-app"));

        Jwt jwt = jwtWithClaims(Map.of("scope", "documents.read"));

        Collection<GrantedAuthority> authorities = converter.convert(jwt);

        assertThat(authorities).containsExactly(new SimpleGrantedAuthority("SCOPE_documents.read"));
    }
}
