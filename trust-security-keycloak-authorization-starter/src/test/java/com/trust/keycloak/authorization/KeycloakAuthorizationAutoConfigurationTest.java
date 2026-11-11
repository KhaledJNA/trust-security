package com.trust.keycloak.authorization;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.context.PropertyPlaceholderAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the wiring contract of {@link KeycloakAuthorizationAutoConfiguration}:
 * the adapter activates only when both the issuer URI and the resource
 * server identifier are configured, backs off when the application already
 * provides its own {@link AuthorizationDecisionClient}, and fails fast
 * (rather than silently) when misconfigured.
 */
class KeycloakAuthorizationAutoConfigurationTest {

    private static final String ISSUER_URI_PROPERTY =
            "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://idp.example.com/realms/lab";
    private static final String KEYCLOAK_AUTHORIZATION_ISSUER_URI_PROPERTY =
            "trust.security.keycloak-authorization.issuer-uri=https://idp.example.com/realms/lab";
    private static final String RESOURCE_SERVER_PROPERTY =
            "trust.security.resource-server.client-id=sample-api";

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    PropertyPlaceholderAutoConfiguration.class,
                    KeycloakAuthorizationAutoConfiguration.class))
            .withBean(ObjectMapper.class, ObjectMapper::new);

    @Test
    void givenIssuerUriAndResourceServerConfigured_whenContextStarts_thenKeycloakAuthorizationDecisionClientBeanIsCreated() {
        contextRunner
                .withPropertyValues(ISSUER_URI_PROPERTY, RESOURCE_SERVER_PROPERTY)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationDecisionClient.class);
                    assertThat(context.getBean(AuthorizationDecisionClient.class))
                            .isInstanceOf(KeycloakAuthorizationDecisionClient.class);
                });
    }

    @Test
    void givenNoIssuerUriConfigured_whenContextStarts_thenStartupFailsFastInsteadOfSilentlyAllowingEverything() {
        contextRunner
                .withPropertyValues(RESOURCE_SERVER_PROPERTY)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasRootCauseMessage("trust.security.keycloak-authorization.issuer-uri is required "
                                    + "(or spring.security.oauth2.resourceserver.jwt.issuer-uri, for a JWT-mode "
                                    + "resource server in the same realm)");
                });
    }

    /**
     * A resource server in opaque-token mode never sets {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}
     * (trust-security-resource-server-starter's {@code TokenFormatGuard} would
     * in fact refuse to start if it did, alongside the opaque properties) -
     * this adapter must still be reachable via its own, format-independent
     * property.
     */
    @Test
    void givenOnlyTheDedicatedIssuerUriPropertyConfigured_whenContextStarts_thenKeycloakAuthorizationDecisionClientBeanIsCreated() {
        contextRunner
                .withPropertyValues(KEYCLOAK_AUTHORIZATION_ISSUER_URI_PROPERTY, RESOURCE_SERVER_PROPERTY)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationDecisionClient.class);
                    assertThat(context.getBean(AuthorizationDecisionClient.class))
                            .isInstanceOf(KeycloakAuthorizationDecisionClient.class);
                });
    }

    /**
     * When both are present, the dedicated property wins - not a merge, not
     * an ambiguity guard: an application deliberately setting both (e.g. a
     * JWT resource server whose UMA adapter genuinely talks to a different
     * realm) gets the more specific one, silently and predictably.
     */
    @Test
    void givenBothIssuerUriPropertiesConfigured_whenContextStarts_thenTheDedicatedPropertyWins() {
        contextRunner
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://wrong.example.com/realms/other",
                        KEYCLOAK_AUTHORIZATION_ISSUER_URI_PROPERTY,
                        RESOURCE_SERVER_PROPERTY)
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void givenNoResourceServerConfigured_whenContextStarts_thenStartupFailsFastInsteadOfSilentlyAllowingEverything() {
        contextRunner
                .withPropertyValues(ISSUER_URI_PROPERTY)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(IllegalStateException.class)
                            .hasRootCauseMessage("trust.security.resource-server.client-id is required");
                });
    }

    @Test
    void givenApplicationSuppliedAuthorizationDecisionClient_whenContextStarts_thenKeycloakDefaultBacksOff() {
        AuthorizationDecisionClient custom = request -> true;

        contextRunner
                .withPropertyValues(ISSUER_URI_PROPERTY, RESOURCE_SERVER_PROPERTY)
                .withBean(AuthorizationDecisionClient.class, () -> custom)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationDecisionClient.class);
                    assertThat(context.getBean(AuthorizationDecisionClient.class)).isSameAs(custom);
                });
    }
}
