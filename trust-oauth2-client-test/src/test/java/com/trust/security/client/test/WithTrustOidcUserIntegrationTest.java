package com.trust.security.client.test;

import com.trust.security.core.acr.RequiresAcr;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.stereotype.Component;
import org.springframework.test.context.TestPropertySource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Full annotation-driven demonstration: OIDC claims become a real
 * {@code OAuth2AuthenticationToken}/{@code OidcUser} through the actual
 * {@code trust-security-oauth2-client-starter} auto-configuration - the very
 * same {@code GrantedAuthoritiesMapper} bean (@code ClaimGrantedAuthoritiesMapper})
 * a real BFF boots - and that identity genuinely drives the real
 * {@code @PreAuthorize} and {@code @RequiresAcr} method security.
 * <pre>
 *   user.json (claims)
 *       -&gt; OidcUserAuthority (raw, like a real OIDC login)
 *       -&gt; real ClaimGrantedAuthoritiesMapper (from OAuth2ClientAutoConfiguration)
 *       -&gt; ROLE_USER
 *       -&gt; @PreAuthorize("hasRole('USER')") granted
 * </pre>
 */
@SpringBootTest(
        classes = WithTrustOidcUserIntegrationTest.TestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@TestPropertySource(properties = {
        "trust.security.post-logout-redirect-uri=http://localhost/logged-out",
        "trust.security.authorities.mappings[0].path=permissions.roles",
        "trust.security.authorities.mappings[0].prefix=ROLE_"
})
class WithTrustOidcUserIntegrationTest {

    @SpringBootApplication
    static class TestApp {

        @Bean
        ClientRegistrationRepository clientRegistrationRepository() {
            ClientRegistration registration = ClientRegistration.withRegistrationId("trust-test-provider")
                    .clientId("test-client")
                    .clientSecret("test-secret")
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                    .authorizationUri("https://idp.example.test/authorize")
                    .tokenUri("https://idp.example.test/token")
                    .scope("openid")
                    .build();
            return new InMemoryClientRegistrationRepository(registration);
        }

        @Component
        static class GuardedService {

            @PreAuthorize("hasRole('USER')")
            String userOnly() {
                return "granted";
            }

            @RequiresAcr("strong")
            String strongOnly() {
                return "granted";
            }
        }
    }

    @Autowired
    private ApplicationContext context;

    private TestApp.GuardedService guardedService() {
        return context.getBean(TestApp.GuardedService.class);
    }

    @Test
    @WithTrustOidcUser("user.json")
    void givenUserClaim_whenCallingRoleGuardedMethod_thenTheRealMappingGrantsAccess() {
        assertThat(guardedService().userOnly()).isEqualTo("granted");
    }

    @Test
    @WithTrustOidcUser("no-roles.json")
    void givenFixtureWithoutUserRole_whenCallingRoleGuardedMethod_thenAccessIsDenied() {
        assertThatExceptionOfType(AuthorizationDeniedException.class)
                .isThrownBy(() -> guardedService().userOnly());
    }

    @Test
    void givenNoAnnotation_whenInspectingSecurityContext_thenNoArtificialAuthenticationExists() {
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }

    @Test
    @WithTrustOidcUser("user.json")
    void givenNoAcrOverride_whenCallingAcrGuardedMethod_thenStepUpIsRequired() {
        assertThatExceptionOfType(AuthorizationDeniedException.class)
                .isThrownBy(() -> guardedService().strongOnly());
    }

    @Test
    @WithTrustOidcUser(value = "user.json", acr = "strong")
    void givenAStrongAcrOverride_whenCallingAcrGuardedMethod_thenAccessIsGranted() {
        assertThat(guardedService().strongOnly()).isEqualTo("granted");
    }

    @Test
    @WithTrustOidcUser("user.json")
    void givenAnnotatedTest_whenInspectingSecurityContextDirectly_thenAGenuineOidcPrincipalIsPresent() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication.getPrincipal())
                .isInstanceOf(org.springframework.security.oauth2.core.oidc.user.OidcUser.class);
    }

    @Test
    void afterEachTest_theSecurityContextIsClearedByTheFramework() {
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
