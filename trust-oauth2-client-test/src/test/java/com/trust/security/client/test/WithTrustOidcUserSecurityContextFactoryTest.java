package com.trust.security.client.test;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit-level tests of the factory, with the optional {@code @Autowired}
 * mapper field set directly via {@link ReflectionTestUtils}. The full
 * annotation-driven flow (a real {@code @SpringBootTest} applying
 * {@code @WithTrustOidcUser}) is covered separately in
 * {@link WithTrustOidcUserIntegrationTest}.
 */
class WithTrustOidcUserSecurityContextFactoryTest {

    @WithTrustOidcUser("user.json")
    private static class Holder1 {
    }

    @WithTrustOidcUser(value = "user.json", subject = "override-subject")
    private static class Holder2 {
    }

    @WithTrustOidcUser(value = "user.json", acr = "strong")
    private static class Holder3 {
    }

    @WithTrustOidcUser(value = "user.json", registrationId = "custom-provider")
    private static class Holder4 {
    }

    private static WithTrustOidcUser annotation(Class<?> holder) {
        return holder.getAnnotation(WithTrustOidcUser.class);
    }

    private static WithTrustOidcUserSecurityContextFactory factory() {
        return new WithTrustOidcUserSecurityContextFactory();
    }

    private static WithTrustOidcUserSecurityContextFactory factoryWithMapper(GrantedAuthoritiesMapper mapper) {
        WithTrustOidcUserSecurityContextFactory factory = factory();
        ReflectionTestUtils.setField(factory, "authoritiesMapper", mapper);
        return factory;
    }

    @Test
    void givenNoMapperConfigured_whenCreatingSecurityContext_thenOnlyTheRawOidcUserAuthorityIsGranted() {
        SecurityContext context = factory().createSecurityContext(annotation(Holder1.class));

        assertThat(context.getAuthentication().getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("OIDC_USER");
    }

    @Test
    void givenAMapper_whenCreatingSecurityContext_thenARealOAuth2AuthenticationTokenWrapsAnOidcUser() {
        WithTrustOidcUserSecurityContextFactory factory =
                factoryWithMapper(authorities -> List.of(new SimpleGrantedAuthority("ROLE_USER")));

        SecurityContext context = factory.createSecurityContext(annotation(Holder1.class));

        assertThat(context.getAuthentication()).isInstanceOf(OAuth2AuthenticationToken.class);
        assertThat(context.getAuthentication().getPrincipal()).isInstanceOf(OidcUser.class);
        assertThat(context.getAuthentication().getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }

    @Test
    void givenASubjectOverrideOnTheAnnotation_whenCreatingSecurityContext_thenTheNameReflectsTheOverride() {
        SecurityContext context = factory().createSecurityContext(annotation(Holder2.class));

        assertThat(context.getAuthentication().getName()).isEqualTo("override-subject");
    }

    @Test
    void givenAnAcrOverrideOnTheAnnotation_whenCreatingSecurityContext_thenThePrincipalCarriesTheAcrClaim() {
        SecurityContext context = factory().createSecurityContext(annotation(Holder3.class));

        OidcUser oidcUser = (OidcUser) context.getAuthentication().getPrincipal();
        assertThat(oidcUser.getClaimAsString("acr")).isEqualTo("strong");
    }

    @Test
    void givenARegistrationIdOnTheAnnotation_whenCreatingSecurityContext_thenTheTokenExposesIt() {
        SecurityContext context = factory().createSecurityContext(annotation(Holder4.class));

        OAuth2AuthenticationToken token = (OAuth2AuthenticationToken) context.getAuthentication();
        assertThat(token.getAuthorizedClientRegistrationId()).isEqualTo("custom-provider");
    }
}
