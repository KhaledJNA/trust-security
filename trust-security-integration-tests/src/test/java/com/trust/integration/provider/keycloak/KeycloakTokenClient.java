package com.trust.integration.provider.keycloak;

import org.springframework.http.MediaType;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.Objects;

/**
 * Obtains real, signed Keycloak access tokens over the real token endpoint -
 * no fake JWT is ever built here.
 * <p>
 * The Resource Server, Authorization/UMA and token-relay contract tests need
 * a genuine bearer token but not the interactive browser hand-off a real end
 * user goes through; the OAuth2 Resource Owner Password Credentials grant
 * (enabled on {@code trust-it-bff} for this purpose only) gets one directly,
 * with the exact (optional) scopes - and therefore audiences - each scenario
 * needs. This is a deliberate shortcut for the token-acquisition step only -
 * it does not replace the real Authorization Code flow exercised end-to-end
 * for the BFF scenario in {@code contract.oauth2client}.
 */
final class KeycloakTokenClient {

    private static final RestClient REST_CLIENT = RestClient.create();

    private KeycloakTokenClient() {
    }

    static String passwordGrantAccessToken(String username, String password, String scope) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "password");
        form.add("client_id", KeycloakTestEnvironment.TOKEN_ISSUER_CLIENT_ID);
        form.add("client_secret", KeycloakTestEnvironment.TOKEN_ISSUER_CLIENT_SECRET);
        form.add("username", username);
        form.add("password", password);
        if (scope != null && !scope.isBlank()) {
            form.add("scope", scope);
        }

        Map<?, ?> response = REST_CLIENT.post()
                .uri(KeycloakTestEnvironment.issuerUri() + "/protocol/openid-connect/token")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(form)
                .retrieve()
                .body(Map.class);

        return (String) Objects.requireNonNull(response, "no token response from Keycloak").get("access_token");
    }
}
