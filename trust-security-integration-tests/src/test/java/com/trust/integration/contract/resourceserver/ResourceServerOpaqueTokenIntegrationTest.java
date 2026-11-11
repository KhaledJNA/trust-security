package com.trust.integration.contract.resourceserver;

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
 * Certifies the opaque-token (RFC 7662 introspection) Resource Server mode
 * against a real Keycloak:
 * <pre>
 *   real access token for trust.user
 *       -&gt; real HTTP "Authorization: Bearer ..." header
 *       -&gt; ResourceServerHarnessApplication, opaque-token mode (no jwt.issuer-uri)
 *       -&gt; Trust's introspector -&gt; real Keycloak introspection endpoint
 *          (authenticated as trust-it-api)
 *       -&gt; Trust's claim mapping on the introspection attributes
 *          (realm_access.roles / resource_access.{clientId}.roles)
 *       -&gt; @PreAuthorize -&gt; 200 / 403, CurrentUserProvider -&gt; the real caller
 * </pre>
 * The token is never decoded locally: Keycloak alone says whether it is
 * active, so a garbage token or a token from another realm is rejected by
 * the real provider.
 */
@SpringBootTest(
        classes = ResourceServerHarnessApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "trust.security.resource-server.client-id=" + KeycloakTestEnvironment.RESOURCE_SERVER_CLIENT_ID,
        "spring.security.oauth2.resourceserver.opaquetoken.client-id=" + KeycloakTestEnvironment.RESOURCE_SERVER_CLIENT_ID,
        "spring.security.oauth2.resourceserver.opaquetoken.client-secret=" + KeycloakTestEnvironment.RESOURCE_SERVER_CLIENT_SECRET,
        "trust.security.authorities.mappings[0].path=realm_access.roles",
        "trust.security.authorities.mappings[0].prefix=ROLE_",
        "trust.security.authorities.mappings[1].path=resource_access.{clientId}.roles",
        "trust.security.authorities.mappings[1].prefix=ROLE_"
})
class ResourceServerOpaqueTokenIntegrationTest {

    @DynamicPropertySource
    static void registerKeycloakProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.opaquetoken.introspection-uri",
                KeycloakTestEnvironment::introspectionUri);
        // Opaque mode has no jwt.issuer-uri to fall back on: the UMA adapter
        // (also on the harness classpath) needs its own issuer.
        registry.add("trust.security.keycloak-authorization.issuer-uri", KeycloakTestEnvironment::issuerUri);
    }

    @LocalServerPort
    private int port;

    private RestClient restClient() {
        return RestClient.builder().baseUrl("http://localhost:" + port).build();
    }

    private HttpStatusCode call(String path, String accessToken) {
        return restClient().get().uri(path)
                .header("Authorization", "Bearer " + accessToken)
                .exchange((req, response) -> response.getStatusCode());
    }

    private static String standardUserToken() {
        return KeycloakTestEnvironment.resourceServerAccessToken(
                KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);
    }

    @Test
    void givenRealActiveToken_whenIntrospected_thenTheRealmRoleIsMappedAndAccessGranted() {
        assertThat(call("/role-protected", standardUserToken()).value()).isEqualTo(200);
    }

    @Test
    void givenRealActiveToken_whenIntrospected_thenTheClientRoleIsMapped() {
        assertThat(call("/reader-protected", standardUserToken()).value()).isEqualTo(200);
    }

    @Test
    void givenRealActiveToken_whenReadingTheCurrentUser_thenItIsTheRealCaller() {
        String username = restClient().get().uri("/me")
                .header("Authorization", "Bearer " + standardUserToken())
                .retrieve()
                .body(String.class);

        assertThat(username).isEqualTo(KeycloakTestEnvironment.STANDARD_USERNAME);
    }

    @Test
    void givenRoleAbsent_whenIntrospected_thenAccessIsForbidden() {
        String accessToken = KeycloakTestEnvironment.resourceServerAccessToken(
                KeycloakTestEnvironment.DENIED_USERNAME, KeycloakTestEnvironment.DENIED_USER_PASSWORD);

        assertThat(call("/role-protected", accessToken).value()).isEqualTo(403);
    }

    @Test
    void givenAnUnknownToken_whenIntrospected_thenTheRealProviderSaysInactive() {
        assertThat(call("/role-protected", "this-is-not-a-real-token").value()).isEqualTo(401);
    }

    @Test
    void givenATokenFromAnotherRealm_whenIntrospected_thenTheRealProviderSaysInactive() {
        assertThat(call("/role-protected", KeycloakTestEnvironment.foreignIssuerAccessToken()).value())
                .isEqualTo(401);
    }
}
