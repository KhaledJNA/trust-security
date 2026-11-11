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
 * Certifies the fine-grained authorization chain against real Keycloak
 * Authorization Services / UMA, with no fake {@code AuthorizationDecisionClient}
 * anywhere:
 * <pre>
 *   @RequiresPermission(resource = "TestResource", scope = "read")
 *       -&gt; real RequiresPermissionAuthorizationManager (trust-security-core)
 *       -&gt; real ResourceServerPermissionChecker (trust-security-resource-server-starter)
 *       -&gt; real KeycloakAuthorizationDecisionClient (trust-security-keycloak-authorization-starter)
 *       -&gt; real Keycloak UMA grant (grant_type=uma-ticket) against the real container
 *       -&gt; PERMIT (trust.user, has TRUST_TEST_USER) / DENY (trust.denied, does not)
 * </pre>
 * This validates the contract between Trust and its Keycloak adapter - see
 * {@code trust-security-test} for the equivalent contract tested with a fake
 * decision client instead, at the application level.
 * <p>
 * The context-driven ("write" scope, Tenant Context Policy) dimension of
 * this same chain is certified separately in
 * {@link UmaContextPolicyIntegrationTest}.
 */
@SpringBootTest(
        classes = ResourceServerHarnessApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "trust.security.resource-server.client-id=" + KeycloakTestEnvironment.AUTHORIZATION_CLIENT_ID,
        "trust.security.authorities.mappings[0].path=realm_access.roles",
        "trust.security.authorities.mappings[0].prefix=ROLE_"
})
class UmaAuthorizationIntegrationTest {

    @DynamicPropertySource
    static void registerKeycloakProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", KeycloakTestEnvironment::issuerUri);
    }

    @LocalServerPort
    private int port;

    private HttpStatusCode call(String path, String accessToken) {
        return RestClient.builder().baseUrl("http://localhost:" + port).build()
                .get()
                .uri(path)
                .header("Authorization", "Bearer " + accessToken)
                .exchange((req, response) -> response.getStatusCode());
    }

    /**
     * A DENY is only meaningful if the token was still accepted by Keycloak:
     * an expired or rejected subject token also ends in 403. So each DENY
     * scenario re-uses the same token on a PERMIT path afterwards - if that
     * still passes, the token was valid when the DENY happened, and the
     * DENY came from the policy decision itself.
     */
    private void assertDeniedByPolicy(String path, String accessToken) {
        assertThat(call(path, accessToken).value()).isEqualTo(403);
        assertThat(call("/resources/1", accessToken).value())
                .as("control: the same token is still permitted on a granted resource")
                .isEqualTo(200);
    }

    private static String userToken() {
        return KeycloakTestEnvironment.authorizationAccessToken(
                KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);
    }

    private static String deniedToken() {
        return KeycloakTestEnvironment.authorizationAccessToken(
                KeycloakTestEnvironment.DENIED_USERNAME, KeycloakTestEnvironment.DENIED_USER_PASSWORD);
    }

    /** 6.1 / 6.2: resource + scope + permission, Role Policy PERMIT - trust.user has TRUST_TEST_USER. */
    @Test
    void givenUserWithTheRequiredRole_whenCheckingPermission_thenRealUmaPermits() {
        assertThat(call("/resources/1", userToken()).value()).isEqualTo(200);
    }

    /**
     * 6.3: Role Policy DENY - trust.denied does not have TRUST_TEST_USER
     * (6.2, the PERMIT side for trust.user, is 6.1 above). trust.denied has
     * no permitted path to serve as a control, so this one relies on 403
     * (authenticated, then denied) rather than 401.
     */
    @Test
    void givenUserWithoutTheRequiredRole_whenCheckingPermission_thenRealUmaDenies() {
        assertThat(call("/resources/1", deniedToken()).value()).isEqualTo(403);
    }

    /** 6.4: a resource never registered in Authorization Services - real Keycloak denies. */
    @Test
    void givenAnUnknownResource_whenCheckingPermission_thenRealUmaDenies() {
        assertDeniedByPolicy("/resources-unknown-resource/1", userToken());
    }

    /** 6.5: a scope never registered on the resource - real Keycloak denies. */
    @Test
    void givenAnUnknownScope_whenCheckingPermission_thenRealUmaDenies() {
        assertDeniedByPolicy("/resources-unknown-scope/1", userToken());
    }

    /** 6.6: resource and scope are valid, but no permission ties them to any policy - real Keycloak denies. */
    @Test
    void givenAValidResourceAndScopeButNoPermission_whenCheckingPermission_thenRealUmaDenies() {
        assertDeniedByPolicy("/resources-unassigned/1", userToken());
    }
}
