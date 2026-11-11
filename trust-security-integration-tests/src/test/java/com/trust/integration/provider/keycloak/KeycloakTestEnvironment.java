package com.trust.integration.provider.keycloak;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.client.ClientBuilder;
import jakarta.ws.rs.client.ClientRequestFilter;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;

import java.io.File;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.List;

/**
 * Owns the single, shared Keycloak Testcontainer used by every contract test
 * in this suite: starting a real Keycloak takes several seconds, so it is
 * started exactly once per JVM (the classic Testcontainers "singleton
 * container" pattern) and left running - Testcontainers' own Ryuk reaper
 * stops it at JVM exit even if a test crashes.
 * <p>
 * Everything Keycloak-specific (image, realm import, admin client, the
 * dynamically-provisioned Authorization Services fixture) is confined to this
 * {@code provider.keycloak} package. Contract test classes only ever see
 * {@link #issuerUri()} and the plain HTTP/OIDC concepts any provider would
 * expose.
 * <p>
 * The realm ({@code trust-integration}), its users, roles and clients form a
 * purely artificial certification universe - no vocabulary borrowed from any
 * demo application or business domain. See the module README for the full
 * inventory.
 */
public final class KeycloakTestEnvironment {

    public static final String REALM = "trust-integration";
    public static final String KEYCLOAK_IMAGE = "quay.io/keycloak/keycloak:26.7.2";

    public static final String STANDARD_USERNAME = "trust.user";
    public static final String STANDARD_USER_PASSWORD = "trust-user-password";
    public static final String ADMIN_USERNAME = "trust.admin";
    public static final String ADMIN_USER_PASSWORD = "trust-admin-password";
    public static final String DENIED_USERNAME = "trust.denied";
    public static final String DENIED_USER_PASSWORD = "trust-denied-password";

    public static final String STANDARD_ROLE = "TRUST_TEST_USER";
    public static final String ADMIN_ROLE = "TRUST_TEST_ADMIN";
    public static final String READER_CLIENT_ROLE = "TRUST_TEST_READER";

    public static final String TOKEN_ISSUER_CLIENT_ID = "trust-it-bff";
    public static final String TOKEN_ISSUER_CLIENT_SECRET = "trust-it-bff-secret";
    public static final String RESOURCE_SERVER_CLIENT_ID = "trust-it-api";
    /** Lets {@link #RESOURCE_SERVER_CLIENT_ID} authenticate to the introspection endpoint (opaque-token mode). */
    public static final String RESOURCE_SERVER_CLIENT_SECRET = "trust-it-api-secret";
    public static final String DOWNSTREAM_RESOURCE_SERVER_CLIENT_ID = "trust-it-api-downstream";
    public static final String AUTHORIZATION_CLIENT_ID = "trust-it-authorization";

    public static final String AUTHORIZATION_RESOURCE_NAME = "TestResource";
    public static final String SCOPE_READ = "read";
    public static final String SCOPE_WRITE = "write";
    public static final String TENANT_CONTEXT_KEY = "tenant";
    public static final String TENANT_A = "TENANT_A";
    public static final String TENANT_B = "TENANT_B";

    public static final KeycloakContainer KEYCLOAK = new KeycloakContainer(KEYCLOAK_IMAGE)
            .withRealmImportFile("keycloak/trust-integration-realm.json")
            // The master realm (which this suite does not control via realm
            // import) defaults to sslRequired=EXTERNAL. Docker Desktop's
            // bridge networking makes the admin login arrive from a
            // non-loopback-looking gateway address, so Keycloak classifies it
            // as "external" and demands HTTPS. Rather than terminate real TLS
            // just to talk to an ephemeral test container, this suite tells
            // Keycloak to trust X-Forwarded-* headers and asserts "https"
            // itself on the one client (see #adminClient()) used purely to
            // provision the fixture - a standard, documented Testcontainers
            // pattern, not a relaxation of anything the tests actually verify
            // (the realm the tests authenticate against - trust-integration -
            // is configured sslRequired=none on its own merits).
            .withEnv("KC_PROXY_HEADERS", "xforwarded")
            // Required for the deployed Script Policy used to certify
            // Trust's claim_token context against a real Keycloak policy
            // decision (see KeycloakAuthorizationServicesFixture). This is
            // the same "Deployed Scripts" SPI mechanism (not the removed
            // "upload JS via Admin API" feature) already used in this
            // environment's own docker-compose Keycloak.
            .withFeaturesEnabled("scripts")
            .withProviderLibsFrom(List.of(tenantContextPolicyJar()));

    private static File tenantContextPolicyJar() {
        URL resource = KeycloakTestEnvironment.class.getClassLoader()
                .getResource("keycloak/tenant-context-policy.jar");
        if (resource == null) {
            throw new IllegalStateException(
                    "keycloak/tenant-context-policy.jar not found on the test classpath - "
                            + "see src/test/resources/keycloak/policy-provider for its source");
        }
        try {
            return new File(resource.toURI());
        } catch (URISyntaxException e) {
            throw new IllegalStateException(e);
        }
    }

    private static volatile Keycloak adminClient;

    static {
        KEYCLOAK.start();
        KeycloakAuthorizationServicesFixture.provisionAuthorizationServices(REALM);
    }

    private KeycloakTestEnvironment() {
    }

    /** The realm's issuer URL, exactly as {@code spring.security.oauth2.resourceserver.jwt.issuer-uri}/{@code provider.*.issuer-uri} expect it. */
    public static String issuerUri() {
        return KEYCLOAK.getAuthServerUrl() + "/realms/" + REALM;
    }

    /** The realm's RFC 7662 token introspection endpoint. */
    public static String introspectionUri() {
        return issuerUri() + "/protocol/openid-connect/token/introspect";
    }

    /** The realm's RP-initiated logout (end session) endpoint. */
    public static String endSessionUri() {
        return issuerUri() + "/protocol/openid-connect/logout";
    }

    /**
     * A real, validly-signed token from the same Keycloak but another realm
     * ({@code master}): another issuer, signed with other keys - for the
     * "token from an untrusted issuer" contract test.
     */
    public static String foreignIssuerAccessToken() {
        return adminClient().tokenManager().getAccessTokenString();
    }

    /** A real, signed access token for {@code username}, carrying the given (space-separated) optional scopes on top of the client's default ones. */
    public static String accessToken(String username, String password, String scope) {
        return KeycloakTokenClient.passwordGrantAccessToken(username, password, scope);
    }

    /** A real access token whose audience includes {@link #RESOURCE_SERVER_CLIENT_ID} - what a plain Resource Server contract test needs. */
    public static String resourceServerAccessToken(String username, String password) {
        return accessToken(username, password, "aud-" + RESOURCE_SERVER_CLIENT_ID);
    }

    /** A real access token deliberately carrying none of the audiences this suite's Resource Servers expect - for the wrong-audience contract test. */
    public static String tokenWithoutResourceServerAudience(String username, String password) {
        return accessToken(username, password, "profile");
    }

    /** A real access token whose audience includes {@link #AUTHORIZATION_CLIENT_ID} - what the UMA contract tests need. */
    public static String authorizationAccessToken(String username, String password) {
        return accessToken(username, password, "aud-" + AUTHORIZATION_CLIENT_ID);
    }

    /** A real access token carrying both {@link #RESOURCE_SERVER_CLIENT_ID} and {@link #DOWNSTREAM_RESOURCE_SERVER_CLIENT_ID} as audience - what the token-relay contract test needs (the same token is relayed as-is downstream). */
    public static String tokenRelayAccessToken(String username, String password) {
        return accessToken(username, password,
                "aud-" + RESOURCE_SERVER_CLIENT_ID + " aud-" + DOWNSTREAM_RESOURCE_SERVER_CLIENT_ID);
    }

    /**
     * Points {@link #TOKEN_ISSUER_CLIENT_ID} at the harness application's
     * actual (dynamically-chosen) redirect URI, through the real Admin API -
     * this cannot be known at realm-import time since this suite never
     * depends on a fixed port.
     */
    public static void registerBffRedirectUri(String redirectUri) {
        KeycloakClientConfigurer.registerRedirectUri(TOKEN_ISSUER_CLIENT_ID, redirectUri);
    }

    /** Points {@link #TOKEN_ISSUER_CLIENT_ID}'s back-channel logout URL at the harness application's actual, dynamically-chosen endpoint. */
    public static void registerBffBackChannelLogoutUrl(String backChannelLogoutUrl) {
        KeycloakClientConfigurer.registerBackChannelLogoutUrl(TOKEN_ISSUER_CLIENT_ID, backChannelLogoutUrl);
    }

    /**
     * The Keycloak Admin Client, authenticated against {@code master} with
     * the container's bootstrap admin credentials - built (rather than using
     * {@link KeycloakContainer#getKeycloakAdminClient()} directly) so a
     * {@code X-Forwarded-Proto: https} header can be attached to its
     * requests, matching {@code KC_PROXY_HEADERS=xforwarded} above.
     */
    static Keycloak adminClient() {
        if (adminClient == null) {
            synchronized (KeycloakTestEnvironment.class) {
                if (adminClient == null) {
                    adminClient = buildAdminClient();
                }
            }
        }
        return adminClient;
    }

    private static Keycloak buildAdminClient() {
        ClientRequestFilter forwardedProtoFilter = requestContext -> {
            requestContext.getHeaders().putSingle("X-Forwarded-Proto", "https");
            requestContext.getHeaders().putSingle("X-Forwarded-For", "127.0.0.1");
        };
        Client httpClient = ClientBuilder.newBuilder()
                .register(forwardedProtoFilter)
                .build();

        return KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK.getAuthServerUrl())
                .realm(KeycloakContainer.MASTER_REALM)
                .clientId(KeycloakContainer.ADMIN_CLI_CLIENT)
                .username(KEYCLOAK.getAdminUsername())
                .password(KEYCLOAK.getAdminPassword())
                .resteasyClient(httpClient)
                .build();
    }
}
