package com.trust.integration.contract.oauth2client;

import com.trust.integration.provider.keycloak.KeycloakBrowserSimulator;
import com.trust.integration.provider.keycloak.KeycloakTestEnvironment;
import com.trust.integration.support.oauth2client.OAuth2ClientHarnessApplication;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.util.UriComponentsBuilder;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.net.http.HttpResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * Certifies the OAuth2 Client / BFF chain against a real Keycloak, through
 * a real browser-like login (no fixture {@code OidcUser}):
 * <pre>
 *   unauthenticated navigation -&gt; redirect to the BFF's authorization endpoint
 *       -&gt; real authorization request (PKCE S256, state, nonce) to Keycloak
 *       -&gt; real login form, real credentials
 *       -&gt; real code exchange + ID token validation by Spring Security
 *       -&gt; Trust's claim mapping (realm_access.roles -&gt; ROLE_*)
 *       -&gt; HTTP session -&gt; CurrentUserProvider / CurrentAuthoritiesProvider
 *       -&gt; @RequiresAcr step-up challenge, RP-initiated logout
 * </pre>
 * The {@code trust-it-bff} client requires PKCE S256 on the Keycloak side,
 * so a successful login also proves the BFF really sends it.
 */
@SpringBootTest(
        classes = OAuth2ClientHarnessApplication.class,
        webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@TestPropertySource(properties = {
        "spring.security.oauth2.client.registration." + OAuth2ClientLoginIntegrationTest.REGISTRATION_ID
                + ".client-id=" + KeycloakTestEnvironment.TOKEN_ISSUER_CLIENT_ID,
        "spring.security.oauth2.client.registration." + OAuth2ClientLoginIntegrationTest.REGISTRATION_ID
                + ".client-secret=" + KeycloakTestEnvironment.TOKEN_ISSUER_CLIENT_SECRET,
        "spring.security.oauth2.client.registration." + OAuth2ClientLoginIntegrationTest.REGISTRATION_ID
                + ".scope=openid,profile,email",
        "trust.security.post-logout-redirect-uri=http://localhost/after-logout",
        "trust.security.authorities.mappings[0].path=realm_access.roles",
        "trust.security.authorities.mappings[0].prefix=ROLE_"
})
class OAuth2ClientLoginIntegrationTest {

    static final String REGISTRATION_ID = "keycloak";

    private static final ObjectMapper JSON = new ObjectMapper();

    @DynamicPropertySource
    static void registerKeycloakProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.client.provider." + REGISTRATION_ID + ".issuer-uri",
                KeycloakTestEnvironment::issuerUri);
    }

    @LocalServerPort
    private int port;

    private final KeycloakBrowserSimulator browser = new KeycloakBrowserSimulator();

    private String baseUrl() {
        return "http://localhost:" + port;
    }

    /** The port is random, so the redirect URI can only be registered once the BFF is up. */
    @BeforeEach
    void registerRedirectUri() {
        KeycloakTestEnvironment.registerBffRedirectUri(baseUrl() + "/login/oauth2/code/" + REGISTRATION_ID);
    }

    private void login(String username, String password) throws Exception {
        browser.loginViaKeycloak(baseUrl(), REGISTRATION_ID, username, password);
    }

    private JsonNode identity() throws Exception {
        HttpResponse<String> response = browser.get(baseUrl() + "/identity");
        assertThat(response.statusCode()).isEqualTo(200);
        return JSON.readTree(response.body());
    }

    private static List<String> authorities(JsonNode identity) {
        List<String> authorities = new ArrayList<>();
        identity.get("authorities").forEach(node -> authorities.add(node.asString()));
        return authorities;
    }

    @Test
    void givenNoSession_whenNavigatingToAProtectedPage_thenTheBrowserIsSentToLogin() throws Exception {
        HttpResponse<String> response = browser.getWithoutRedirect(baseUrl() + "/identity", Map.of());

        assertThat(response.statusCode()).isEqualTo(302);
        assertThat(response.headers().firstValue("Location")).hasValueSatisfying(location ->
                assertThat(location).contains("/oauth2/authorization/" + REGISTRATION_ID));
    }

    @Test
    void whenStartingLogin_thenTheRealAuthorizationRequestCarriesPkceS256StateAndNonce() throws Exception {
        HttpResponse<String> response = browser.getWithoutRedirect(
                baseUrl() + "/oauth2/authorization/" + REGISTRATION_ID, Map.of());

        assertThat(response.statusCode()).isEqualTo(302);
        URI location = URI.create(response.headers().firstValue("Location").orElseThrow());
        Map<String, List<String>> query = UriComponentsBuilder.fromUri(location).build().getQueryParams();

        assertThat(location.getPath()).endsWith("/realms/" + KeycloakTestEnvironment.REALM + "/protocol/openid-connect/auth");
        assertThat(query).containsKeys("code_challenge", "state", "nonce");
        assertThat(query.get("code_challenge_method")).containsExactly("S256");
        assertThat(query.get("client_id")).containsExactly(KeycloakTestEnvironment.TOKEN_ISSUER_CLIENT_ID);
    }

    @Test
    void givenRealLogin_whenReadingTheSessionIdentity_thenItIsTheRealUserWithMappedRealmRoles() throws Exception {
        login(KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);

        JsonNode identity = identity();

        assertThat(identity.get("authenticated").asBoolean()).isTrue();
        assertThat(identity.get("username").asString()).isEqualTo(KeycloakTestEnvironment.STANDARD_USERNAME);
        assertThat(identity.get("subject").asString()).isNotBlank();
        assertThat(authorities(identity)).contains("ROLE_" + KeycloakTestEnvironment.STANDARD_ROLE);
    }

    @Test
    void givenRealLoginOfAUserWithoutTheRole_whenReadingTheSessionIdentity_thenTheRoleIsAbsent() throws Exception {
        login(KeycloakTestEnvironment.DENIED_USERNAME, KeycloakTestEnvironment.DENIED_USER_PASSWORD);

        List<String> authorities = authorities(identity());

        assertThat(authorities).doesNotContain("ROLE_" + KeycloakTestEnvironment.STANDARD_ROLE);
        assertThat(authorities).noneMatch(authority -> authority.startsWith("ROLE_TRUST_TEST"));
    }

    @Test
    void givenWrongPassword_whenLoggingIn_thenNoSessionIsEstablished() throws Exception {
        assertThatIllegalStateException().isThrownBy(() ->
                login(KeycloakTestEnvironment.STANDARD_USERNAME, "not-the-password"));

        HttpResponse<String> response = browser.getWithoutRedirect(baseUrl() + "/identity", Map.of());
        assertThat(response.statusCode()).isEqualTo(302);
    }

    @Test
    void givenRealLoginWithoutTheRequiredAcr_whenCallingAnAcrProtectedEndpoint_thenAStepUpChallengeIsReturned()
            throws Exception {
        login(KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);

        HttpResponse<String> response = browser.getWithoutRedirect(baseUrl() + "/strong", Map.of());

        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("WWW-Authenticate")).hasValueSatisfying(challenge ->
                assertThat(challenge)
                        .contains("insufficient_user_authentication")
                        .contains("acr_values=\"strong\""));
    }

    @Test
    void givenRealLogin_whenLoggingOut_thenTheSessionEndsAndTheBrowserIsSentToTheProviderLogout() throws Exception {
        login(KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);
        identity(); // any request issues the CSRF cookie
        String csrfToken = browser.cookie(baseUrl(), "XSRF-TOKEN").orElseThrow();

        HttpResponse<String> logout = browser.postFormWithoutRedirect(
                baseUrl() + "/logout", Map.of("X-XSRF-TOKEN", csrfToken), "");

        assertThat(logout.statusCode()).isEqualTo(302);
        assertThat(logout.headers().firstValue("Location")).hasValueSatisfying(location -> assertThat(location)
                .startsWith(KeycloakTestEnvironment.endSessionUri())
                .contains("id_token_hint="));

        HttpResponse<String> afterLogout = browser.getWithoutRedirect(baseUrl() + "/identity", Map.of());
        assertThat(afterLogout.statusCode()).isEqualTo(302);
    }

    @Test
    void givenRealLogin_whenLoggingOutWithoutTheCsrfToken_thenTheLogoutIsRefused() throws Exception {
        login(KeycloakTestEnvironment.STANDARD_USERNAME, KeycloakTestEnvironment.STANDARD_USER_PASSWORD);

        HttpResponse<String> logout = browser.postFormWithoutRedirect(baseUrl() + "/logout", Map.of(), "");

        assertThat(logout.statusCode()).isEqualTo(403);
        assertThat(identity().get("authenticated").asBoolean()).isTrue();
    }
}
