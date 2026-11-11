package com.trust.security.resourceserver.test;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class TrustTestJwtsTest {

    @Test
    void givenExistingJsonFixture_whenLoadingClaims_thenClaimsAreParsedIncludingNestedStructures() {
        Map<String, Object> claims = TrustTestJwts.loadClaims("user.json");

        assertThat(claims).containsEntry("sub", "user-123");
        assertThat(claims).containsEntry("preferred_username", "sample-user");
        @SuppressWarnings("unchecked")
        Map<String, Object> permissions = (Map<String, Object>) claims.get("permissions");
        assertThat(permissions).containsEntry("roles", List.of("USER"));
    }

    @Test
    void givenMissingFixture_whenLoadingClaims_thenIllegalArgumentExceptionNamesTheResource() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> TrustTestJwts.loadClaims("does-not-exist.json"))
                .withMessageContaining("does-not-exist.json");
    }

    @Test
    void givenInvalidJsonFixture_whenLoadingClaims_thenIllegalArgumentExceptionNamesTheResource() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> TrustTestJwts.loadClaims("invalid.json"))
                .withMessageContaining("invalid.json");
    }

    @Test
    void givenNullResourceName_whenLoadingClaims_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() -> TrustTestJwts.loadClaims(null));
    }

    @Test
    void givenClaimsWithSubject_whenBuildingJwt_thenSubjectIsPreserved() {
        Jwt jwt = TrustTestJwts.jwt(Map.of("sub", "user-123"));

        assertThat(jwt.getSubject()).isEqualTo("user-123");
    }

    @Test
    void givenClaimsWithoutSubject_whenBuildingJwt_thenANeutralDefaultSubjectIsUsed() {
        Jwt jwt = TrustTestJwts.jwt(Map.of("preferred_username", "someone"));

        assertThat(jwt.getSubject()).isNotBlank();
        assertThat(jwt.getSubject()).doesNotContainIgnoringCase("keycloak");
    }

    @Test
    void givenASubjectOverride_whenBuildingJwt_thenItReplacesTheFixtureSubject() {
        Jwt jwt = TrustTestJwts.jwt(Map.of("sub", "user-123"), "user-999");

        assertThat(jwt.getSubject()).isEqualTo("user-999");
    }

    @Test
    void givenNestedClaims_whenBuildingJwt_thenTheyAreAccessibleUnchanged() {
        Jwt jwt = TrustTestJwts.jwt(Map.of(
                "sub", "user-123",
                "permissions", Map.of("roles", List.of("USER"))));

        assertThat(jwt.getClaimAsMap("permissions")).containsEntry("roles", List.of("USER"));
    }

    @Test
    void whenBuildingJwt_thenItIsCurrentlyValid() {
        Instant before = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        Jwt jwt = TrustTestJwts.jwt(Map.of("sub", "user-123"));

        assertThat(jwt.getTokenValue()).isEqualTo("trust-test-jwt");
        assertThat(jwt.getHeaders()).isNotEmpty();
        assertThat(jwt.getIssuedAt()).isBetween(before, Instant.now());
        assertThat(jwt.getExpiresAt()).isAfter(Instant.now());
        assertThat(jwt.getClaimAsInstant("exp")).isEqualTo(jwt.getExpiresAt());
    }

    @Test
    void givenFixtureTimestamps_whenBuildingJwt_thenTheyWin() {
        Jwt jwt = TrustTestJwts.jwt(Map.of("sub", "user-123", "iat", 1_000, "exp", 2_000));

        assertThat(jwt.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(1_000));
        assertThat(jwt.getExpiresAt()).isEqualTo(Instant.ofEpochSecond(2_000));
    }
}
