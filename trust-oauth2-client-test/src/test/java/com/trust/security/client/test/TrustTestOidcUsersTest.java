package com.trust.security.client.test;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class TrustTestOidcUsersTest {

    @Test
    void givenExistingJsonFixture_whenLoadingClaims_thenClaimsAreParsedIncludingNestedStructures() {
        Map<String, Object> claims = TrustTestOidcUsers.loadClaims("user.json");

        assertThat(claims).containsEntry("sub", "user-123");
        @SuppressWarnings("unchecked")
        Map<String, Object> permissions = (Map<String, Object>) claims.get("permissions");
        assertThat(permissions).containsEntry("roles", List.of("USER"));
    }

    @Test
    void givenMissingFixture_whenLoadingClaims_thenIllegalArgumentExceptionNamesTheResource() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> TrustTestOidcUsers.loadClaims("does-not-exist.json"))
                .withMessageContaining("does-not-exist.json");
    }

    @Test
    void givenInvalidJsonFixture_whenLoadingClaims_thenIllegalArgumentExceptionNamesTheResource() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> TrustTestOidcUsers.loadClaims("invalid.json"))
                .withMessageContaining("invalid.json");
    }

    @Test
    void givenNullResourceName_whenLoadingClaims_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() -> TrustTestOidcUsers.loadClaims(null));
    }

    @Test
    void givenClaimsWithSubject_whenBuildingIdToken_thenSubjectIsPreserved() {
        OidcIdToken idToken = TrustTestOidcUsers.idToken(Map.of("sub", "user-123"));

        assertThat(idToken.getSubject()).isEqualTo("user-123");
    }

    @Test
    void givenNoSubject_whenBuildingIdToken_thenANeutralDefaultIsUsed() {
        OidcIdToken idToken = TrustTestOidcUsers.idToken(Map.of("preferred_username", "someone"));

        assertThat(idToken.getSubject()).isNotBlank();
        assertThat(idToken.getSubject()).doesNotContainIgnoringCase("keycloak");
    }

    @Test
    void givenASubjectOverride_whenBuildingIdToken_thenItReplacesTheFixtureSubject() {
        OidcIdToken idToken = TrustTestOidcUsers.idToken(Map.of("sub", "user-123"), "user-999", null);

        assertThat(idToken.getSubject()).isEqualTo("user-999");
    }

    @Test
    void givenAnAcrOverride_whenBuildingIdToken_thenTheAcrClaimIsSet() {
        OidcIdToken idToken = TrustTestOidcUsers.idToken(Map.of("sub", "user-123"), null, "strong");

        assertThat(idToken.getClaimAsString("acr")).isEqualTo("strong");
    }

    @Test
    void whenBuildingIdToken_thenItIsCurrentlyValid() {
        Instant before = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        OidcIdToken idToken = TrustTestOidcUsers.idToken(Map.of("sub", "user-123"));

        assertThat(idToken.getTokenValue()).isEqualTo("trust-test-id-token");
        assertThat(idToken.getIssuedAt()).isBetween(before, Instant.now());
        assertThat(idToken.getExpiresAt()).isAfter(Instant.now());
        assertThat(idToken.getClaimAsInstant("exp")).isEqualTo(idToken.getExpiresAt());
    }

    @Test
    void givenFixtureTimestamps_whenBuildingIdToken_thenTheyWin() {
        OidcIdToken idToken = TrustTestOidcUsers.idToken(Map.of("sub", "user-123", "iat", 1_000, "exp", 2_000));

        assertThat(idToken.getIssuedAt()).isEqualTo(Instant.ofEpochSecond(1_000));
        assertThat(idToken.getExpiresAt()).isEqualTo(Instant.ofEpochSecond(2_000));
    }

    @Test
    void givenNumericAuthTime_whenBuildingIdToken_thenItIsReadableAsAnInstant() {
        OidcIdToken idToken = TrustTestOidcUsers.idToken(Map.of("sub", "user-123", "auth_time", 1_500));

        assertThat(idToken.getAuthenticatedAt()).isEqualTo(Instant.ofEpochSecond(1_500));
    }

    @Test
    void givenNoAuthoritiesMapper_whenBuildingAuthenticationToken_thenOnlyTheRawOidcUserAuthorityIsGranted() {
        OAuth2AuthenticationToken token = TrustTestOidcUsers.authenticationToken(
                Map.of("sub", "user-123"), null, null, "trust-test-provider", null);

        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("OIDC_USER");
    }

    @Test
    void whenBuildingAuthenticationToken_thenThePrincipalIsARealOidcUserCarryingTheClaims() {
        OAuth2AuthenticationToken token = TrustTestOidcUsers.authenticationToken(
                Map.of("sub", "user-123", "preferred_username", "sample-user"),
                null, null, "trust-test-provider", null);

        assertThat(token.getPrincipal()).isInstanceOf(OidcUser.class);
        OidcUser oidcUser = (OidcUser) token.getPrincipal();
        assertThat(oidcUser.getSubject()).isEqualTo("user-123");
        assertThat(oidcUser.getClaimAsString("preferred_username")).isEqualTo("sample-user");
    }

    @Test
    void whenBuildingAuthenticationToken_thenTheRegistrationIdIsExposed() {
        OAuth2AuthenticationToken token = TrustTestOidcUsers.authenticationToken(
                Map.of("sub", "user-123"), null, null, "my-provider", null);

        assertThat(token.getAuthorizedClientRegistrationId()).isEqualTo("my-provider");
    }

    @Test
    void givenAnAuthoritiesMapper_whenBuildingAuthenticationToken_thenItIsAppliedToTheRawOidcUserAuthority() {
        OAuth2AuthenticationToken token = TrustTestOidcUsers.authenticationToken(
                Map.of("sub", "user-123"), null, null, "trust-test-provider",
                authorities -> List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertThat(token.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }
}
