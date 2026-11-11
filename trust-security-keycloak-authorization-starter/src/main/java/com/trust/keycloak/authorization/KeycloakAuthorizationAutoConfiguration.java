package com.trust.keycloak.authorization;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestClient;
import tools.jackson.databind.ObjectMapper;

/**
 * Auto-configuration for the Keycloak Authorization Services / UMA adapter.
 * <p>
 * This is the only place in the Trust security libraries allowed to know about
 * Keycloak's UMA grant flow. Applications opt into it simply by adding this
 * module as a dependency; trust-security-resource-server-starter itself
 * stays provider-neutral and only depends on the {@link AuthorizationDecisionClient}
 * abstraction from trust-security-core.
 * <p>
 * The UMA "resource server" identifier (the {@code audience} sent to
 * Keycloak) is read from {@code trust.security.resource-server.client-id} -
 * the same property the resource-server starter already requires for JWT
 * audience validation, and which, in this deployment, is also the client's
 * own UMA resource server identifier. Reading it here directly (rather than
 * depending on trust-security-resource-server-starter's properties type)
 * avoids a Maven dependency between the two starters.
 * <p>
 * The realm's issuer URI - needed only to build the UMA token endpoint
 * ({@code issuerUri + "/protocol/openid-connect/token"}), nothing to do with
 * how the resource server validates its own incoming tokens - is read from
 * {@code trust.security.keycloak-authorization.issuer-uri}, a property
 * specific to this adapter and independent of the resource server's token
 * format. When absent, it falls back to {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}
 * (the common case: a JWT-mode resource server's issuer is the same realm
 * this adapter talks to, so nothing extra needs configuring). An opaque-mode
 * resource server - which never sets that JWT property - must set
 * {@code trust.security.keycloak-authorization.issuer-uri} explicitly.
 */
@AutoConfiguration
public class KeycloakAuthorizationAutoConfiguration {

    private static final String PROTOCOL_OPENID_CONNECT_TOKEN = "/protocol/openid-connect/token";

    @Bean
    @ConditionalOnMissingBean(AuthorizationDecisionClient.class)
    public AuthorizationDecisionClient authorizationDecisionClient(
            @Value("${trust.security.keycloak-authorization.issuer-uri:${spring.security.oauth2.resourceserver.jwt.issuer-uri:}}")
            String issuerUri,
            @Value("${trust.security.resource-server.client-id:}") String resourceServer,
            ObjectMapper objectMapper) {

        if (issuerUri == null || issuerUri.isBlank()) {
            throw new IllegalStateException(
                    "trust.security.keycloak-authorization.issuer-uri is required "
                    + "(or spring.security.oauth2.resourceserver.jwt.issuer-uri, for a JWT-mode resource server "
                    + "in the same realm)"
            );
        }

        if (resourceServer == null || resourceServer.isBlank()) {
            throw new IllegalStateException(
                    "trust.security.resource-server.client-id is required"
            );
        }

        return new KeycloakAuthorizationDecisionClient(
                RestClient.create(),
                issuerUri + PROTOCOL_OPENID_CONNECT_TOKEN,
                resourceServer,
                objectMapper
        );
    }
}
