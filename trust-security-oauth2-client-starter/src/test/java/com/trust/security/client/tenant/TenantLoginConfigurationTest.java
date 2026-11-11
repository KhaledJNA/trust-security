package com.trust.security.client.tenant;

import com.trust.security.client.OAuth2ClientAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Wiring of {@link TenantLoginConfiguration}, through the full
 * {@link OAuth2ClientAutoConfiguration}: beans created or not, and every
 * startup validation of {@code registration-id-resolution}.
 */
class TenantLoginConfigurationTest {

    private static final String POST_LOGOUT_REDIRECT_URI_PROPERTY =
            "trust.security.post-logout-redirect-uri=http://127.0.0.1:8081/";

    private static ClientRegistration clientRegistration(String registrationId) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId("my-app")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://idp.example.com/auth")
                .tokenUri("https://idp.example.com/token")
                .userNameAttributeName("sub")
                .clientName(registrationId)
                .scope("openid")
                .build();
    }

    private static final String HOST_RESOLUTION_PROPERTIES_PREFIX =
            "trust.security.oauth2-client.login.registration-id-resolution";

    private WebApplicationContextRunner contextRunner() {
        return new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class))
                .withBean(ClientRegistrationRepository.class, () -> new InMemoryClientRegistrationRepository(
                        clientRegistration("keycloak-acme"), clientRegistration("keycloak-globex")))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(POST_LOGOUT_REDIRECT_URI_PROPERTY);
    }

    @Test
    void givenNoRegistrationIdResolutionConfigured_whenContextStarts_thenNoTenantBeansAreCreated() {
        contextRunner().run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(TrustRegistrationIdResolver.class);
            assertThat(context).doesNotHaveBean(TenantLoginRequestFilter.class);
        });
    }

    @Test
    void givenHostBasedRegistrationIdResolutionConfigured_whenContextStarts_thenResolverAndFilterAreCreated() {
        contextRunner()
                .withPropertyValues(
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".request-pattern=/sso/login",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".source=host",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.acme.application.fr=keycloak-acme",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.globex.application.fr=keycloak-globex")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(TrustRegistrationIdResolver.class);
                    assertThat(context.getBean(TrustRegistrationIdResolver.class))
                            .isInstanceOf(HostTrustRegistrationIdResolver.class);
                    assertThat(context).hasSingleBean(TenantLoginRequestFilter.class);
                });
    }

    @Test
    void givenPathBasedRegistrationIdResolutionConfigured_whenContextStarts_thenPathResolverIsCreated() {
        contextRunner()
                .withPropertyValues(
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".request-pattern=/sso/login/{tenant}",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".source=path",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".variable-name=tenant",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.acme=keycloak-acme",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.globex=keycloak-globex")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(TrustRegistrationIdResolver.class))
                            .isInstanceOf(PathVariableTrustRegistrationIdResolver.class);
                });
    }

    @Test
    void givenMappingReferencesUnknownRegistrationId_whenContextStarts_thenItFailsNamingIt() {
        contextRunner()
                .withPropertyValues(
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".request-pattern=/sso/login",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".source=host",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.acme.application.fr=does-not-exist")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(RegistrationIdResolutionConfigurationException.class)
                            .hasMessageContaining("does-not-exist");
                });
    }

    @Test
    void givenApplicationSuppliedResolverAndRequestPatternOverlappingSpringEndpoint_whenContextStarts_thenItStillFails() {
        TrustRegistrationIdResolver custom = request -> java.util.Optional.of("keycloak-acme");

        contextRunner()
                .withBean(TrustRegistrationIdResolver.class, () -> custom)
                .withPropertyValues(
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".request-pattern=/login/oauth2/code/{tenant}",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".source=host",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.acme.application.fr=keycloak-acme")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(RegistrationIdResolutionConfigurationException.class);
                });
    }

    @Test
    void givenRequestPatternOverlapsOAuth2AuthorizationEndpoint_whenContextStarts_thenItFails() {
        contextRunner()
                .withPropertyValues(
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".request-pattern=/oauth2/authorization/extra",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".source=host",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.acme.application.fr=keycloak-acme")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(RegistrationIdResolutionConfigurationException.class);
                });
    }

    @Test
    void givenPathSourceWithoutVariableName_whenContextStarts_thenItFails() {
        contextRunner()
                .withPropertyValues(
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".request-pattern=/sso/login/{tenant}",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".source=path",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.acme=keycloak-acme")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(RegistrationIdResolutionConfigurationException.class);
                });
    }

    @Test
    void givenHostSourceWithVariableNameSet_whenContextStarts_thenItFails() {
        contextRunner()
                .withPropertyValues(
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".request-pattern=/sso/login",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".source=host",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".variable-name=tenant",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.acme.application.fr=keycloak-acme")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(RegistrationIdResolutionConfigurationException.class);
                });
    }

    @Test
    void givenApplicationSuppliedTrustRegistrationIdResolver_whenContextStarts_thenTrustDefaultBacksOff() {
        TrustRegistrationIdResolver custom = request -> java.util.Optional.of("keycloak-acme");

        contextRunner()
                .withBean(TrustRegistrationIdResolver.class, () -> custom)
                .withPropertyValues(
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".request-pattern=/sso/login",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".source=host",
                        HOST_RESOLUTION_PROPERTIES_PREFIX + ".mappings.acme.application.fr=keycloak-acme")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(TrustRegistrationIdResolver.class);
                    assertThat(context.getBean(TrustRegistrationIdResolver.class)).isSameAs(custom);
                    assertThat(context).hasSingleBean(TenantLoginRequestFilter.class);
                });
    }
}
