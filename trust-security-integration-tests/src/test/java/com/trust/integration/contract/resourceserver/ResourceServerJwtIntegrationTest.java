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
 * Certifies the Resource Server chain against a real Keycloak, with no
 * shortcut at any step:
 * <pre>
 *   Keycloak Testcontainer (real container, real realm import)
 *       -&gt; real access token for trust.user (password grant, real signature)
 *       -&gt; real HTTP "Authorization: Bearer ..." header
 *       -&gt; ResourceServerHarnessApplication (trust-security-resource-server-starter, unmodified)
 *       -&gt; real JwtDecoder (real issuer, real JWKS, real signature verification)
 *       -&gt; real audience validator
 *       -&gt; real JwtClaimAuthoritiesConverter (realm_access.roles / resource_access.{clientId}.roles)
 *       -&gt; @PreAuthorize
 *       -&gt; 200 / 403
 * </pre>
 * This is precisely what {@code trust-resource-server-test} (fixture JWT, no
 * signature/JWKS/issuer/audience) deliberately does not exercise - see its
 * own README.
 */
@SpringBootTest(
        classes = ResourceServerHarnessApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "trust.security.resource-server.client-id=" + KeycloakTestEnvironment.RESOURCE_SERVER_CLIENT_ID,
        "trust.security.authorities.mappings[0].path=realm_access.roles",
        "trust.security.authorities.mappings[0].prefix=ROLE_",
        "trust.security.authorities.mappings[1].path=resource_access.{clientId}.roles",
        "trust.security.authorities.mappings[1].prefix=ROLE_"
})
class ResourceServerJwtIntegrationTest {

    @DynamicPropertySource
    static void registerKeycloakProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", KeycloakTestEnvironment::issuerUri);
    }

    @LocalServerPort
    private int port;

    private RestClient restClient() {
        return RestClient.builder().baseUrl("http://localhost:" + port).build();
    }

    private HttpStatusCode call(String path, String accessToken) {
        RestClient.RequestHeadersSpec<?> request = restClient().get().uri(path);
        if (accessToken != null) {
            request = request.header("Authorization", "Bearer " + accessToken);
        }
        return request.exchange((req, response) -> response.getStatusCode());
    }

    /** 5.1: a real, valid JWT for a member of TRUST_TEST_USER grants access - full real chain. */
    @Test
    void givenRealValidToken_whenCallingRoleProtectedEndpoint_thenTheRealChainGrantsAccess() {
        String accessToken = KeycloakTestEnvironment.resourceServerAccessToken(
                KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);

        String body = restClient().get().uri("/role-protected")
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .body(String.class);

        assertThat(body).isNotBlank();
    }

    /** 5.2: a real, valid JWT for a user without TRUST_TEST_USER is denied. */
    @Test
    void givenRoleAbsent_whenCallingRoleProtectedEndpoint_thenAccessIsForbidden() {
        String accessToken = KeycloakTestEnvironment.resourceServerAccessToken(
                KeycloakTestEnvironment.DENIED_USERNAME, KeycloakTestEnvironment.DENIED_USER_PASSWORD);

        assertThat(call("/role-protected", accessToken).value()).isEqualTo(403);
    }

    /** 5.3: no token at all. */
    @Test
    void givenNoBearerToken_whenCallingProtectedEndpoint_thenUnauthorized() {
        assertThat(call("/role-protected", null).value()).isEqualTo(401);
    }

    /** 5.4: a syntactically invalid token, rejected by the real JwtDecoder. */
    @Test
    void givenAnInvalidToken_whenCallingProtectedEndpoint_thenTheRealJwtDecoderRejectsIt() {
        assertThat(call("/role-protected", "this-is-not-a-real-jwt").value()).isEqualTo(401);
    }

    /**
     * 5.5: a real, validly-signed token from the real Keycloak, deliberately
     * requested without this Resource Server's audience - certifies the real
     * Trust audience validator, not just JWT well-formedness.
     */
    @Test
    void givenARealTokenWithTheWrongAudience_whenCallingProtectedEndpoint_thenTheRealAudienceValidatorRejectsIt() {
        // Not STANDARD_USERNAME: it holds a trust-it-api client role, and Keycloak's built-in
        // "audience resolve" mapper (default "roles" scope) then adds trust-it-api to aud anyway.
        String accessToken = KeycloakTestEnvironment.tokenWithoutResourceServerAudience(
                KeycloakTestEnvironment.ADMIN_USERNAME, KeycloakTestEnvironment.ADMIN_USER_PASSWORD);

        assertThat(call("/role-protected", accessToken).value()).isEqualTo(401);
    }

    /** 5.6: realm role mapping, explicitly - realm_access.roles -> ROLE_TRUST_TEST_USER. */
    @Test
    void givenRealmAccessRolesClaim_whenConverted_thenTheExpectedRealmRoleAuthorityIsGranted() {
        String accessToken = KeycloakTestEnvironment.resourceServerAccessToken(
                KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);

        assertThat(call("/role-protected", accessToken).value()).isEqualTo(200);
    }

    /** 5.7: client role mapping - resource_access.trust-it-api.roles -> ROLE_TRUST_TEST_READER. */
    @Test
    void givenResourceAccessClientRoleForThisClientId_whenCallingReaderProtectedEndpoint_thenAccessIsGranted() {
        String accessToken = KeycloakTestEnvironment.resourceServerAccessToken(
                KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);

        assertThat(call("/reader-protected", accessToken).value()).isEqualTo(200);
    }

    /** 5.7 (negative): a user without the client role is denied by the same real chain. */
    @Test
    void givenNoResourceAccessClientRole_whenCallingReaderProtectedEndpoint_thenAccessIsForbidden() {
        String accessToken = KeycloakTestEnvironment.resourceServerAccessToken(
                KeycloakTestEnvironment.DENIED_USERNAME, KeycloakTestEnvironment.DENIED_USER_PASSWORD);

        assertThat(call("/reader-protected", accessToken).value()).isEqualTo(403);
    }

    /**
     * 5.8: a real, validly-signed token from the same Keycloak but another
     * realm (another issuer, other signing keys) - certifies that only the
     * configured issuer is trusted, not "any token this server could fetch
     * keys for".
     */
    @Test
    void givenARealTokenFromAnotherIssuer_whenCallingProtectedEndpoint_thenItIsRejected() {
        assertThat(call("/role-protected", KeycloakTestEnvironment.foreignIssuerAccessToken()).value())
                .isEqualTo(401);
    }

    /** 5.9: Trust's CurrentUserProvider exposes the real caller of a real JWT. */
    @Test
    void givenRealValidToken_whenReadingTheCurrentUser_thenItIsTheRealCaller() {
        String accessToken = KeycloakTestEnvironment.resourceServerAccessToken(
                KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);

        String username = restClient().get().uri("/me")
                .header("Authorization", "Bearer " + accessToken)
                .retrieve()
                .body(String.class);

        assertThat(username).isEqualTo(KeycloakTestEnvironment.STANDARD_USERNAME);
    }
}
