package com.trust.security.client.authorities;

import com.trust.security.core.role.AuthorityClaimMapping;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

/**
 * Behavioral tests for {@link ClaimGrantedAuthoritiesMapper}.
 * <p>
 * Deliberately uses fictitious, vendor-neutral claim shapes ({@code permissions.roles},
 * {@code organization.groups}) rather than any real identity provider's claims - this
 * mapper, like {@link ClaimAuthoritiesMapper} in trust-security-core, must stay
 * provider-neutral. Keycloak-shaped mappings are exercised in the demo application's
 * own configuration, not here.
 * <p>
 * None of these tests construct or reference an access token: the mapper's input type
 * ({@code Collection<? extends GrantedAuthority>}) structurally prevents any access
 * token assumption - there simply is no access token in scope.
 */
class ClaimGrantedAuthoritiesMapperTest {

    private static OidcIdToken idToken(Map<String, Object> claims) {
        OidcIdToken.Builder builder = OidcIdToken.withTokenValue("id-token-value")
                .subject("user-1")
                .issuedAt(Instant.EPOCH)
                .expiresAt(Instant.EPOCH.plusSeconds(3600));
        claims.forEach(builder::claim);
        return builder.build();
    }

    private static OidcUserAuthority oidcUserAuthority(Map<String, Object> idTokenClaims) {
        return new OidcUserAuthority(idToken(idTokenClaims));
    }

    private static OidcUserAuthority oidcUserAuthority(
            Map<String, Object> idTokenClaims, Map<String, Object> userInfoClaims) {
        return new OidcUserAuthority(idToken(idTokenClaims), new OidcUserInfo(userInfoClaims));
    }

    @Test
    void givenNullClaimAuthoritiesMapper_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new ClaimGrantedAuthoritiesMapper(null));
    }

    @Test
    void givenOidcUserAuthorityWithConfiguredClaim_whenMapping_thenBusinessAuthorityIsAdded() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of(
                        new AuthorityClaimMapping("permissions.roles", "ROLE_", null))));

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(
                List.of(oidcUserAuthority(Map.of("permissions", Map.of("roles", List.of("user"))))));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("OIDC_USER", "ROLE_user");
    }

    @Test
    void givenOidcUserAuthorityWithoutConfiguredClaim_whenMapping_thenNoBusinessAuthorityIsAdded() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of(
                        new AuthorityClaimMapping("permissions.roles", "ROLE_", null))));

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(
                List.of(oidcUserAuthority(Map.of("sub", "user-1"))));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .containsExactly("OIDC_USER");
    }

    @Test
    void givenExistingSpringAuthorities_whenMapping_thenTheyArePreservedAsTheSameInstances() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of()));
        GrantedAuthority existing = new SimpleGrantedAuthority("SCOPE_openid");

        List<GrantedAuthority> result = List.copyOf(mapper.mapAuthorities(List.of(existing)));

        assertThat(result).contains(existing);
    }

    @Test
    void givenSeveralInputAuthorities_whenMapping_thenAllAreConserved() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of()));
        GrantedAuthority scopeOpenid = new SimpleGrantedAuthority("SCOPE_openid");
        GrantedAuthority scopeProfile = new SimpleGrantedAuthority("SCOPE_profile");
        OidcUserAuthority oidcUser = oidcUserAuthority(Map.of("sub", "user-1"));

        Collection<? extends GrantedAuthority> result =
                mapper.mapAuthorities(List.of(scopeOpenid, scopeProfile, oidcUser));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("SCOPE_openid", "SCOPE_profile", "OIDC_USER");
    }

    @Test
    void givenMultipleRolesConfigured_whenMapping_thenAllAreAdded() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of(
                        new AuthorityClaimMapping("permissions.roles", "ROLE_", null))));

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(
                List.of(oidcUserAuthority(Map.of(
                        "permissions", Map.of("roles", List.of("user", "offline_access", "uma_authorization"))))));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder(
                        "OIDC_USER", "ROLE_user", "ROLE_offline_access", "ROLE_uma_authorization");
    }

    @Test
    void givenComputedAuthorityDuplicatesAnExistingOne_whenMapping_thenResultIsDeduplicated() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of(
                        new AuthorityClaimMapping("permissions.roles", "ROLE_", null))));
        GrantedAuthority alreadyPresent = new SimpleGrantedAuthority("ROLE_user");

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(List.of(
                alreadyPresent,
                oidcUserAuthority(Map.of("permissions", Map.of("roles", List.of("user"))))));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_user", "OIDC_USER");
    }

    @Test
    void givenNoMappingsConfigured_whenMapping_thenSpringAuthoritiesAreUnchanged() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of()));

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(
                List.of(oidcUserAuthority(Map.of("permissions", Map.of("roles", List.of("user"))))));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .containsExactly("OIDC_USER");
    }

    @Test
    void givenClaimOnlyInIdToken_whenMapping_thenItIsUsed() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of(
                        new AuthorityClaimMapping("organization.groups", "GROUP_", null))));

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(List.of(
                oidcUserAuthority(
                        Map.of("organization", Map.of("groups", List.of("finance"))),
                        Map.of("sub", "user-1"))));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .contains("GROUP_finance");
    }

    @Test
    void givenClaimOnlyInUserInfo_whenMapping_thenItIsAlsoUsed() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of(
                        new AuthorityClaimMapping("organization.groups", "GROUP_", null))));

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(List.of(
                oidcUserAuthority(
                        Map.of(),
                        Map.of("organization", Map.of("groups", List.of("finance"))))));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .contains("GROUP_finance");
    }

    @Test
    void givenSameClaimInIdTokenAndUserInfo_whenMapping_thenIdTokenValueTakesPrecedence() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of(
                        new AuthorityClaimMapping("organization.groups", "GROUP_", null))));

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(List.of(
                oidcUserAuthority(
                        Map.of("organization", Map.of("groups", List.of("id-token-group"))),
                        Map.of("organization", Map.of("groups", List.of("userinfo-group"))))));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .contains("GROUP_id-token-group")
                .doesNotContain("GROUP_userinfo-group");
    }

    @Test
    void givenAGenericNonOidcOAuth2UserAuthority_whenMapping_thenItsAttributesAreAlsoUsed() {
        ClaimGrantedAuthoritiesMapper mapper = new ClaimGrantedAuthoritiesMapper(
                new ClaimAuthoritiesMapper(List.of(
                        new AuthorityClaimMapping("permissions.roles", "ROLE_", null))));
        OAuth2UserAuthority genericAuthority = new OAuth2UserAuthority(
                Map.of("permissions", Map.of("roles", List.of("user"))));

        Collection<? extends GrantedAuthority> result = mapper.mapAuthorities(List.of(genericAuthority));

        assertThat(result).extracting(GrantedAuthority::getAuthority)
                .containsExactlyInAnyOrder("OAUTH2_USER", "ROLE_user");
    }
}
