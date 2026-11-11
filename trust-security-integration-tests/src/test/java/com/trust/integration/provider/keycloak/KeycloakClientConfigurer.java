package com.trust.integration.provider.keycloak;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.ClientResource;
import org.keycloak.representations.idm.ClientRepresentation;

import java.util.List;

/**
 * Mutates a client's configuration after realm import, through the real
 * Admin API - used for the pieces of the BFF/OIDC scenarios that cannot be
 * known statically: the harness application's redirect URI and back-channel
 * logout URL, both of which depend on a port picked at test run time (never
 * a fixed port, per this suite's own rule).
 */
final class KeycloakClientConfigurer {

    private KeycloakClientConfigurer() {
    }

    static void registerRedirectUri(String clientId, String redirectUri) {
        ClientRepresentation representation = clientRepresentation(clientId);
        representation.setRedirectUris(List.of(redirectUri));
        update(clientId, representation);
    }

    static void registerBackChannelLogoutUrl(String clientId, String backChannelLogoutUrl) {
        ClientRepresentation representation = clientRepresentation(clientId);
        representation.getAttributes().put("backchannel.logout.url", backChannelLogoutUrl);
        representation.getAttributes().put("backchannel.logout.session.required", "true");
        update(clientId, representation);
    }

    private static ClientRepresentation clientRepresentation(String clientId) {
        return clientResource(clientId).toRepresentation();
    }

    private static void update(String clientId, ClientRepresentation representation) {
        clientResource(clientId).update(representation);
    }

    private static ClientResource clientResource(String clientId) {
        Keycloak admin = KeycloakTestEnvironment.adminClient();
        String clientUuid = admin.realm(KeycloakTestEnvironment.REALM)
                .clients()
                .findByClientId(clientId)
                .stream()
                .findFirst()
                .map(ClientRepresentation::getId)
                .orElseThrow(() -> new IllegalStateException("Client '" + clientId + "' not found"));
        return admin.realm(KeycloakTestEnvironment.REALM).clients().get(clientUuid);
    }
}
