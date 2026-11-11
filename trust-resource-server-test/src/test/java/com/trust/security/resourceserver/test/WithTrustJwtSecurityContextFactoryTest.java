package com.trust.security.resourceserver.test;

import com.trust.security.resourceserver.authorities.JwtClaimAuthoritiesConverter;
import com.trust.security.core.role.AuthorityClaimMapping;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import org.junit.jupiter.api.Test;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Collection;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Unit-level tests of the factory, with the {@code @Autowired} converter
 * field set directly via {@link ReflectionTestUtils} - the same technique
 * used throughout the Spring ecosystem to test {@code @Autowired}-injected
 * collaborators without booting a full context. The full annotation-driven
 * flow (a real {@code @SpringBootTest} applying {@code @WithTrustJwt}) is
 * covered separately in {@link WithTrustJwtIntegrationTest}.
 */
class WithTrustJwtSecurityContextFactoryTest {

    @WithTrustJwt("user.json")
    private static class Holder1 {
    }

    @WithTrustJwt(value = "user.json", subject = "override-subject")
    private static class Holder2 {
    }

    @WithTrustJwt("no-roles.json")
    private static class Holder3 {
    }

    private static WithTrustJwt annotation(Class<?> holder) {
        return holder.getAnnotation(WithTrustJwt.class);
    }

    private static WithTrustJwtSecurityContextFactory factoryWithConverter(
            Collection<GrantedAuthority> fixedAuthorities) {
        WithTrustJwtSecurityContextFactory factory = new WithTrustJwtSecurityContextFactory();
        Converter<Jwt, Collection<GrantedAuthority>> converter = jwt -> fixedAuthorities;
        ReflectionTestUtils.setField(factory, "authoritiesConverter", converter);
        return factory;
    }

    private static WithTrustJwtSecurityContextFactory factoryWithRealConverter() {
        ClaimAuthoritiesMapper mapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("permissions.roles", "ROLE_", null)));
        WithTrustJwtSecurityContextFactory factory = new WithTrustJwtSecurityContextFactory();
        ReflectionTestUtils.setField(
                factory, "authoritiesConverter", new JwtClaimAuthoritiesConverter(mapper, null));
        return factory;
    }

    @Test
    void givenNoConverterBeanAvailable_whenCreatingSecurityContext_thenFailsExplicitly() {
        WithTrustJwtSecurityContextFactory factory = new WithTrustJwtSecurityContextFactory();

        assertThatIllegalStateException()
                .isThrownBy(() -> factory.createSecurityContext(annotation(Holder1.class)))
                .withMessageContaining("Converter<Jwt");
    }

    @Test
    void givenAConverter_whenCreatingSecurityContext_thenAJwtAuthenticationTokenIsBuiltFromTheFixture() {
        WithTrustJwtSecurityContextFactory factory =
                factoryWithConverter(List.of(new SimpleGrantedAuthority("ROLE_USER")));

        SecurityContext context = factory.createSecurityContext(annotation(Holder1.class));

        assertThat(context.getAuthentication()).isNotNull();
        assertThat(context.getAuthentication().isAuthenticated()).isTrue();
        assertThat(context.getAuthentication().getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER");
    }

    @Test
    void givenAConverter_whenCreatingSecurityContext_thenThePrincipalIsTheRealJwtCarryingTheFixtureClaims() {
        WithTrustJwtSecurityContextFactory factory = factoryWithConverter(List.of());

        SecurityContext context = factory.createSecurityContext(annotation(Holder1.class));

        Object principal = context.getAuthentication().getPrincipal();
        assertThat(principal).isInstanceOf(Jwt.class);
        Jwt jwt = (Jwt) principal;
        assertThat(jwt.getSubject()).isEqualTo("user-123");
        assertThat(jwt.getClaimAsString("preferred_username")).isEqualTo("sample-user");
    }

    @Test
    void givenASubjectOverrideOnTheAnnotation_whenCreatingSecurityContext_thenTheNameReflectsTheOverride() {
        WithTrustJwtSecurityContextFactory factory = factoryWithConverter(List.of());

        SecurityContext context = factory.createSecurityContext(annotation(Holder2.class));

        assertThat(context.getAuthentication().getName()).isEqualTo("override-subject");
    }

    @Test
    void givenTheRealClaimAuthoritiesMapperConverter_whenClaimPathMatches_thenRoleUserIsProduced() {
        WithTrustJwtSecurityContextFactory factory = factoryWithRealConverter();

        SecurityContext context = factory.createSecurityContext(annotation(Holder1.class));

        assertThat(context.getAuthentication().getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .contains("ROLE_USER");
    }

    @Test
    void givenTheRealClaimAuthoritiesMapperConverter_whenFixtureHasNoMatchingRoles_thenRoleUserIsAbsent() {
        WithTrustJwtSecurityContextFactory factory = factoryWithRealConverter();

        SecurityContext context = factory.createSecurityContext(annotation(Holder3.class));

        assertThat(context.getAuthentication().getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .doesNotContain("ROLE_USER");
    }

    /**
     * The whole point of this module: a misconfigured claim mapping path
     * (here, a mapping that does not match the fixture's actual claim shape)
     * makes ROLE_USER absent, exactly as it would in production - not
     * because the test lies about it, but because the real mapping logic ran.
     */
    @Test
    void givenAMisconfiguredMappingPath_whenConverting_thenRoleUserIsAbsentEvenThoughTheFixtureGrantsIt() {
        ClaimAuthoritiesMapper misconfiguredMapper = new ClaimAuthoritiesMapper(
                List.of(new AuthorityClaimMapping("wrong.path.roles", "ROLE_", null)));
        WithTrustJwtSecurityContextFactory factory = new WithTrustJwtSecurityContextFactory();
        ReflectionTestUtils.setField(
                factory, "authoritiesConverter", new JwtClaimAuthoritiesConverter(misconfiguredMapper, null));

        SecurityContext context = factory.createSecurityContext(annotation(Holder1.class));

        assertThat(context.getAuthentication().getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .doesNotContain("ROLE_USER");
    }
}
