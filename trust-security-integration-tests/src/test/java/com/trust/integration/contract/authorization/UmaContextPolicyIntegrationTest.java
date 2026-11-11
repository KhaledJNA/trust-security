package com.trust.integration.contract.authorization;

import com.trust.integration.provider.keycloak.KeycloakTestEnvironment;
import com.trust.integration.support.resourceserver.ResourceServerHarnessApplication;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatusCode;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestClient;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Certifies the full {@code claim_token} context chain against a real
 * Keycloak policy that genuinely consumes it - not merely that Trust sends
 * something that looks right:
 * <pre>
 *   PermissionContextProvider (tenant, resolved from the resource id)
 *       -&gt; AuthorizationRequest
 *       -&gt; KeycloakAuthorizationDecisionClient (trust-security-keycloak-authorization-starter)
 *       -&gt; claim_token construction (base64 JSON)
 *       -&gt; real UMA request
 *       -&gt; real Keycloak
 *       -&gt; a real, deployed Script Policy ("Tenant Context Policy") reads the
 *          "tenant" attribute and decides
 *       -&gt; PERMIT / DENY
 * </pre>
 * The identity making the call (trust.user) and the permission requested
 * ("TestResource#write") are held constant across both tests below - only
 * the resource id (and therefore the tenant the harness's own
 * {@code PermissionContextProvider} resolves) changes. If the final decision
 * changes too, the context genuinely drove it; it is not a fixed answer some
 * other input (identity, resource, scope) already determined.
 * <p>
 * The Script Policy is deployed through Keycloak's
 * "Deployed Scripts" SPI (Keycloak {@code --features=scripts}), not the
 * removed "upload JS via Admin API" feature. See
 * {@code src/test/resources/keycloak/policy-provider} for the deployed
 * script's source and the suite README for the full mechanics.
 */
@SpringBootTest(
        classes = ResourceServerHarnessApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "trust.security.resource-server.client-id=" + KeycloakTestEnvironment.AUTHORIZATION_CLIENT_ID,
        "trust.security.authorities.mappings[0].path=realm_access.roles",
        "trust.security.authorities.mappings[0].prefix=ROLE_"
})
class UmaContextPolicyIntegrationTest {

    @DynamicPropertySource
    static void registerKeycloakProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", KeycloakTestEnvironment::issuerUri);
    }

    @LocalServerPort
    private int port;

    private HttpStatusCode putResource(long id, String accessToken) {
        return RestClient.builder().baseUrl("http://localhost:" + port).build()
                .put()
                .uri("/resources/{id}", id)
                .header("Authorization", "Bearer " + accessToken)
                .exchange((req, response) -> response.getStatusCode());
    }

    private static String userToken() {
        return KeycloakTestEnvironment.authorizationAccessToken(
                KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);
    }

    @Test
    void givenTenantA_whenWritingTheResource_thenTheRealScriptPolicyPermits() {
        assertThat(putResource(1L, userToken()).value()).isEqualTo(200);
    }

    @Test
    void givenTenantB_sameUserSameResourceSameScope_whenWritingTheResource_thenTheRealScriptPolicyDenies() {
        String accessToken = userToken();

        assertThat(putResource(2L, accessToken).value()).isEqualTo(403);
        assertThat(putResource(1L, accessToken).value())
                .as("control: the same token, same user and scope, is still permitted for TENANT_A")
                .isEqualTo(200);
    }
}
