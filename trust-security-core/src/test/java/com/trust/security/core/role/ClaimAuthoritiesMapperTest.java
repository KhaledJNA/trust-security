package com.trust.security.core.role;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import java.util.HashMap;
import java.util.Arrays;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behavioral tests for {@link ClaimAuthoritiesMapper}.
 *
 * <p>trust-security-core is provider-neutral: these tests deliberately use
 * fictitious, vendor-neutral claim shapes ({@code permissions.roles},
 * {@code application.<clientId>.roles}, {@code organization.groups}) instead
 * of any real identity provider's claims. Provider-specific mappings (e.g.
 * Keycloak's {@code realm_access}/{@code resource_access}) are configuration
 * data supplied by the starters and applications, and are covered by their
 * own tests, not here.
 */
class ClaimAuthoritiesMapperTest {

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUp() {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ClaimAuthoritiesMapper.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        logger.addAppender(logAppender);
        logger.setLevel(Level.DEBUG);
    }

    @AfterEach
    void tearDown() {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ClaimAuthoritiesMapper.class);
        logger.detachAppender(logAppender);
        logger.setLevel(null);
    }

    private static Collection<GrantedAuthority> authorities(String... values) {
        return List.of(values).stream()
                .map(v -> (GrantedAuthority) new SimpleGrantedAuthority(v))
                .toList();
    }

    @Test
    void givenNullClaims_whenMapping_thenNoAuthorityIsReturned() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("permissions.roles", "ROLE_", null)));

        Collection<GrantedAuthority> result = mapper.map(null, Map.of());

        assertThat(result).isEmpty();
    }

    @Test
    void givenNoMappingsConfigured_whenMapping_thenNoAuthorityIsReturnedEvenWithClaimsPresent() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of());

        Collection<GrantedAuthority> result = mapper.map(
                Map.of("permissions", Map.of("roles", List.of("admin"))), Map.of());

        assertThat(result).isEmpty();
    }

    @Test
    void givenNullMappingsList_whenConstructing_thenTreatedAsNoMappings() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(null);

        Collection<GrantedAuthority> result = mapper.map(
                Map.of("permissions", Map.of("roles", List.of("admin"))), Map.of());

        assertThat(result).isEmpty();
    }

    @Test
    void givenMappingPathAbsentFromClaims_whenMapping_thenNoAuthorityForThatMapping() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("permissions.roles", "ROLE_", null)));

        Collection<GrantedAuthority> result = mapper.map(Map.of("sub", "user-1"), Map.of());

        assertThat(result).isEmpty();
    }

    @Test
    void givenNestedPath_whenMapping_thenValuesAreResolvedAndPrefixed() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("permissions.roles", "ROLE_", null)));
        Map<String, Object> claims = Map.of(
                "permissions", Map.of("roles", List.of("admin", "auditor")));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(
                authorities("ROLE_admin", "ROLE_auditor"));
    }

    @Test
    void givenSeveralMappings_whenMapping_thenAuthoritiesFromAllMappingsAreMerged() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("permissions.roles", "ROLE_", null),
                new AuthorityClaimMapping("organization.groups", "GROUP_", null)));
        Map<String, Object> claims = Map.of(
                "permissions", Map.of("roles", List.of("admin")),
                "organization", Map.of("groups", List.of("finance")));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(
                authorities("ROLE_admin", "GROUP_finance"));
    }

    @Test
    void givenMapping_whenMapping_thenConfiguredPrefixIsAppliedToEachValue() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("groups", "GROUP_", null)));

        Collection<GrantedAuthority> result = mapper.map(
                Map.of("groups", List.of("finance")), Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(authorities("GROUP_finance"));
    }

    @Test
    void givenSameResultingAuthorityFromDifferentMappings_whenMapping_thenItIsNotDuplicated() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(List.of(
                new AuthorityClaimMapping("permissions.roles", "ROLE_", null),
                new AuthorityClaimMapping("organization.groups", "ROLE_", null)));
        Map<String, Object> claims = Map.of(
                "permissions", Map.of("roles", List.of("admin")),
                "organization", Map.of("groups", List.of("admin")));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(authorities("ROLE_admin"));
    }

    @Test
    void givenIntermediateSegmentNotShapedAsAMap_whenMapping_thenItIsTreatedAsAbsentWithoutError() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("permissions.roles", "ROLE_", null)));

        Collection<GrantedAuthority> result = mapper.map(
                Map.of("permissions", "not-a-map"), Map.of());

        assertThat(result).isEmpty();
    }

    @Test
    void givenDeeplyNestedIntermediateSegmentNotShapedAsAMap_whenMapping_thenItIsTreatedAsAbsentWithoutError() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("application.my-app.roles", "ROLE_", null)));

        Collection<GrantedAuthority> result = mapper.map(
                Map.of("application", Map.of("my-app", "not-a-map")), Map.of());

        assertThat(result).isEmpty();
    }

    @Test
    void givenResolvedValueIsASingleString_whenMapping_thenOneAuthorityIsProducedFromTheWholeValue() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("role", "ROLE_", null)));

        Collection<GrantedAuthority> result = mapper.map(Map.of("role", "admin"), Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(authorities("ROLE_admin"));
    }

    @Test
    void givenResolvedValueIsASingleStringWithSeparatorConfiguredAndMultipleValues_whenMapping_thenOneAuthorityPerValue() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("scope", "SCOPE_", " ")));

        Collection<GrantedAuthority> result = mapper.map(
                Map.of("scope", "documents.read documents.write"), Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(
                authorities("SCOPE_documents.read", "SCOPE_documents.write"));
    }

    @Test
    void givenResolvedValueIsAList_whenMappingWithASeparatorConfigured_thenTheSeparatorIsIgnoredAndBehaviorIsUnchanged() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("permissions.roles", "ROLE_", ",")));

        Collection<GrantedAuthority> result = mapper.map(
                Map.of("permissions", Map.of("roles", List.of("admin", "auditor"))), Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(
                authorities("ROLE_admin", "ROLE_auditor"));
    }

    @Test
    void givenResolvedValueIsAStringContainingASpaceAndNoSeparatorConfigured_whenMapping_thenExactlyOneAuthorityIsProduced() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("name", "NAME_", null)));

        Collection<GrantedAuthority> result = mapper.map(Map.of("name", "Jean Dupont"), Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(authorities("NAME_Jean Dupont"));
    }

    @Test
    void givenResolvedValueIsABoolean_whenMapping_thenNoAuthorityIsProducedAndADebugTraceIsLogged() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("is_admin", "ROLE_", null)));

        Collection<GrantedAuthority> result = mapper.map(Map.of("is_admin", true), Map.of());

        assertThat(result).isEmpty();
        assertThat(logAppender.list)
                .hasSize(1)
                .first()
                .satisfies(event -> {
                    assertThat(event.getLevel()).isEqualTo(Level.DEBUG);
                    assertThat(event.getFormattedMessage())
                            .contains("is_admin")
                            .contains("Boolean");
                });
    }

    @Test
    void givenResolvedValueIsANumber_whenMapping_thenNoAuthorityIsProducedAndADebugTraceIsLogged() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("level", "LEVEL_", null)));

        Collection<GrantedAuthority> result = mapper.map(Map.of("level", 3), Map.of());

        assertThat(result).isEmpty();
        assertThat(logAppender.list).hasSize(1);
        assertThat(logAppender.list.get(0).getLevel()).isEqualTo(Level.DEBUG);
    }

    @Test
    void givenResolvedValueIsAnEmptyList_whenMapping_thenNoAuthorityIsReturned() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("permissions.roles", "ROLE_", null)));

        Collection<GrantedAuthority> result = mapper.map(
                Map.of("permissions", Map.of("roles", List.of())), Map.of());

        assertThat(result).isEmpty();
    }

    @Test
    void givenPathWithClientIdPlaceholder_whenMapping_thenPlaceholderIsResolvedFromVariables() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("application.{clientId}.roles", "APP_", null)));
        Map<String, Object> claims = Map.of(
                "application", Map.of("my-app", Map.of("roles", List.of("editor"))));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of("clientId", "my-app"));

        assertThat(result).containsExactlyInAnyOrderElementsOf(authorities("APP_editor"));
    }

    @Test
    void givenPathWithClientIdPlaceholder_whenMappingForADifferentClient_thenThoseValuesAreNotLeaked() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("application.{clientId}.roles", "APP_", null)));
        Map<String, Object> claims = Map.of(
                "application", Map.of("other-app", Map.of("roles", List.of("editor"))));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of("clientId", "my-app"));

        assertThat(result).isEmpty();
    }

    @Test
    void givenPlaceholderVariableIsMissing_whenMapping_thenNoAuthorityForThatMappingWithoutError() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("application.{clientId}.roles", "APP_", null)));
        Map<String, Object> claims = Map.of(
                "application", Map.of("my-app", Map.of("roles", List.of("editor"))));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of());

        assertThat(result).isEmpty();
    }

    @Test
    void givenPathResolvingToMultipleValues_whenMapping_thenAllValuesAreMappedToAuthorities() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("permissions.roles", "ROLE_", null)));
        Map<String, Object> claims = Map.of(
                "permissions", Map.of("roles", List.of("admin", "auditor", "support")));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of());

        assertThat(result).containsExactlyInAnyOrderElementsOf(
                authorities("ROLE_admin", "ROLE_auditor", "ROLE_support"));
    }

    @Test
    void givenClientIdContainingDots_whenMappingClientRolePath_thenPlaceholderIsResolvedAsOneSegment() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("resource_access.{clientId}.roles", "ROLE_", null)));
        Map<String, Object> claims = Map.of("resource_access",
                Map.of("api.documents", Map.of("roles", List.of("reader"))));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of("clientId", "api.documents"));

        assertThat(result).containsExactly(new SimpleGrantedAuthority("ROLE_reader"));
    }

    @Test
    void givenListClaimWithNonStringNullAndBlankElements_whenMapping_thenOnlyNonBlankStringsBecomeAuthorities() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("roles", "ROLE_", null)));
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", Arrays.asList("admin", 42, null, " ", Map.of("nested", "x"), "user"));

        Collection<GrantedAuthority> result = mapper.map(claims, Map.of());

        assertThat(result).containsExactly(
                new SimpleGrantedAuthority("ROLE_admin"),
                new SimpleGrantedAuthority("ROLE_user"));
    }

    @Test
    void givenBlankStringClaim_whenMapping_thenNoAuthorityIsProduced() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("role", "ROLE_", null)));

        assertThat(mapper.map(Map.of("role", ""), Map.of())).isEmpty();
    }
}
