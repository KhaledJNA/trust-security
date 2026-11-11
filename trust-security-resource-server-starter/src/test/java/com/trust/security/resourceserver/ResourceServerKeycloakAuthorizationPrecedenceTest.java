package com.trust.security.resourceserver;

import com.trust.security.resourceserver.authorization.ResourceServerPermissionChecker;
import com.trust.keycloak.authorization.KeycloakAuthorizationAutoConfiguration;
import com.trust.keycloak.authorization.KeycloakAuthorizationDecisionClient;
import com.trust.security.client.OAuth2ClientAutoConfiguration;
import com.trust.security.core.authorization.AuthorizationDecisionClient;
import com.trust.security.core.authorization.PermissionChecker;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Verifies that when both {@code trust-security-resource-server-starter} and
 * {@code trust-security-keycloak-authorization-starter} are present, the
 * {@link AuthorizationDecisionClient} actually wired into
 * {@link ResourceServerPermissionChecker} is Keycloak's, regardless of which
 * auto-configuration is evaluated first - guarding against a regression of
 * the {@link org.springframework.beans.factory.ObjectProvider} resolution
 * that makes the {@code AuthorizationDecisionClient} optional.
 * <p>
 * {@link KeycloakAuthorizationAutoConfiguration#authorizationDecisionClient}
 * never performs a network call at construction time (it only builds a
 * {@code RestClient.create()}), so no mock server is needed here.
 * <p>
 * Filters out {@code OAuth2ClientAutoConfiguration} from the classloader:
 * {@code trust-security-oauth2-client-starter} is a real test-scope Maven
 * dependency of this module (needed by {@link ResourceServerOAuth2ClientMultiChainTest}),
 * so without this filter every context built here would trip the
 * cohabitation guard, which checks classpath presence and cannot otherwise
 * tell a real application dependency apart from a fellow test class
 * incidentally reachable from the same JVM.
 */
class ResourceServerKeycloakAuthorizationPrecedenceTest {

    private static final String CLIENT_ID_PROPERTY =
            "trust.security.resource-server.client-id=sample-api";
    private static final String ISSUER_URI_PROPERTY =
            "spring.security.oauth2.resourceserver.jwt.issuer-uri=https://issuer.example.com/realms/trust";

    private WebApplicationContextRunner baseRunner() {
        return new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withBean(JwtDecoder.class, () -> mock(JwtDecoder.class))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(CLIENT_ID_PROPERTY, ISSUER_URI_PROPERTY);
    }

    @Test
    void givenResourceServerAutoConfigurationEvaluatedFirst_thenTheKeycloakClientIsStillUsed() {
        baseRunner()
                .withConfiguration(AutoConfigurations.of(
                        ResourceServerAutoConfiguration.class,
                        KeycloakAuthorizationAutoConfiguration.class))
                .run(this::assertKeycloakClientIsWired);
    }

    @Test
    void givenKeycloakAuthorizationAutoConfigurationEvaluatedFirst_thenTheKeycloakClientIsStillUsed() {
        baseRunner()
                .withConfiguration(AutoConfigurations.of(
                        KeycloakAuthorizationAutoConfiguration.class,
                        ResourceServerAutoConfiguration.class))
                .run(this::assertKeycloakClientIsWired);
    }

    private void assertKeycloakClientIsWired(
            org.springframework.boot.test.context.assertj.AssertableWebApplicationContext context) {

        // Only wiring/precedence is asserted here, deliberately without invoking
        // isAllowed(...): KeycloakAuthorizationDecisionClient only maps a 403 to
        // false (see its Javadoc) and would otherwise propagate a real network
        // exception against this non-resolvable issuer - out of scope for this
        // fast unit test. The live refusal path is exercised for real in the
        // dedicated HTTP-level verification (no Keycloak, mock issuer instead).
        assertThat(context).hasNotFailed();
        assertThat(context).hasSingleBean(AuthorizationDecisionClient.class);
        assertThat(context.getBean(AuthorizationDecisionClient.class))
                .isInstanceOf(KeycloakAuthorizationDecisionClient.class);

        PermissionChecker permissionChecker = context.getBean(PermissionChecker.class);
        assertThat(permissionChecker).isInstanceOf(ResourceServerPermissionChecker.class);
    }
}
