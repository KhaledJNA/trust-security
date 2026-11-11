package com.trust.integration.provider.keycloak;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.ClientScopeRepresentation;
import org.keycloak.representations.idm.ProtocolMapperRepresentation;

import java.util.List;
import java.util.Map;

/**
 * Provisions the three optional, per-audience client scopes
 * ({@code aud-trust-it-api}, {@code aud-trust-it-authorization},
 * {@code aud-trust-it-api-downstream}) used to control exactly which
 * audience(s) a given password-grant token request carries - most notably
 * so a token can deliberately be requested <em>without</em> the audience a
 * given Resource Server expects (see the wrong-audience contract test).
 * <p>
 * Done through the Admin API after realm import rather than a top-level
 * {@code clientScopes} array in the realm JSON: Keycloak's realm importer
 * treats a non-empty {@code clientScopes} array as replacing the built-in
 * default scopes entirely (rather than adding to them), which silently
 * broke {@code profile}/{@code email}/{@code roles} - a real, worth-documenting
 * finding (see the suite's final report).
 */
final class KeycloakClientScopeConfigurer {

    private KeycloakClientScopeConfigurer() {
    }

    static void provisionAudienceScopesAndAssignToBff(String realm) {
        Keycloak admin = KeycloakTestEnvironment.adminClient();

        createAudienceScope(realm, "aud-" + KeycloakTestEnvironment.RESOURCE_SERVER_CLIENT_ID,
                KeycloakTestEnvironment.RESOURCE_SERVER_CLIENT_ID);
        createAudienceScope(realm, "aud-" + KeycloakTestEnvironment.AUTHORIZATION_CLIENT_ID,
                KeycloakTestEnvironment.AUTHORIZATION_CLIENT_ID);
        createAudienceScope(realm, "aud-" + KeycloakTestEnvironment.DOWNSTREAM_RESOURCE_SERVER_CLIENT_ID,
                KeycloakTestEnvironment.DOWNSTREAM_RESOURCE_SERVER_CLIENT_ID);

        ClientResource bff = clientResource(realm, KeycloakTestEnvironment.TOKEN_ISSUER_CLIENT_ID);
        for (ClientScopeRepresentation scope : admin.realm(realm).clientScopes().findAll()) {
            if (scope.getName().startsWith("aud-")) {
                bff.addOptionalClientScope(scope.getId());
            }
        }
    }

    private static void createAudienceScope(String realm, String scopeName, String audienceClientId) {
        Keycloak admin = KeycloakTestEnvironment.adminClient();

        ClientScopeRepresentation scope = new ClientScopeRepresentation();
        scope.setName(scopeName);
        scope.setProtocol("openid-connect");
        scope.setAttributes(Map.of(
                "include.in.token.scope", "true",
                "display.on.consent.screen", "false"));

        ProtocolMapperRepresentation audienceMapper = new ProtocolMapperRepresentation();
        audienceMapper.setName("audience");
        audienceMapper.setProtocol("openid-connect");
        audienceMapper.setProtocolMapper("oidc-audience-mapper");
        audienceMapper.setConfig(Map.of(
                "included.client.audience", audienceClientId,
                "id.token.claim", "false",
                "access.token.claim", "true",
                "introspection.token.claim", "true"));
        scope.setProtocolMappers(List.of(audienceMapper));

        admin.realm(realm).clientScopes().create(scope).close();
    }

    private static ClientResource clientResource(String realm, String clientId) {
        Keycloak admin = KeycloakTestEnvironment.adminClient();
        String clientUuid = admin.realm(realm)
                .clients()
                .findByClientId(clientId)
                .stream()
                .findFirst()
                .map(ClientRepresentation::getId)
                .orElseThrow(() -> new IllegalStateException("Client '" + clientId + "' not found"));
        return admin.realm(realm).clients().get(clientUuid);
    }
}
