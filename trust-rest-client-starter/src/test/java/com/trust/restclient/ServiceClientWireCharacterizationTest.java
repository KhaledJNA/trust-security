package com.trust.restclient;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import com.trust.restclient.error.ServiceClientResponseException;
import com.trust.restclient.fixture.wire.WireClient;
import com.trust.restclient.fixture.wire.WireClientCreds;
import com.trust.restclient.fixture.wire.WireClientCredsPackageMarker;
import com.trust.restclient.fixture.wire.WirePackageMarker;
import io.github.resilience4j.circuitbreaker.CallNotPermittedException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.restclient.autoconfigure.RestClientAutoConfiguration;
import org.springframework.boot.http.client.autoconfigure.service.HttpServiceClientPropertiesAutoConfiguration;
import org.springframework.boot.restclient.autoconfigure.service.HttpServiceClientAutoConfiguration;
import org.springframework.boot.ssl.DefaultSslBundleRegistry;
import org.springframework.boot.ssl.SslBundle;
import org.springframework.boot.ssl.SslBundleKey;
import org.springframework.boot.ssl.SslBundles;
import org.springframework.boot.ssl.SslStoreBundle;
import org.springframework.boot.ssl.jks.JksSslStoreBundle;
import org.springframework.boot.ssl.jks.JksSslStoreDetails;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.Executors;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;
import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Characterizes the <b>observable, on-the-wire behavior</b> of a client
 * declared with {@code @ImportHttpServices}, independently of which internal
 * classes produce it - the wire assertions are the contract any internal
 * refactoring must keep.
 *
 * <p>Each test starts its own real {@link HttpServer} (JDK-native, no new
 * test dependency) and asserts on what it actually received - headers,
 * method, body, number of calls - and/or on what the caller actually got
 * back, never on the type of any Trust interceptor/converter class.
 */
class ServiceClientWireCharacterizationTest {

    private HttpServer server;

    private final Map<String, List<RecordedRequest>> received = new HashMap<>();
    private final Map<String, Deque<CannedResponse>> planned = new HashMap<>();
    private volatile long slowResponseDelayMillis = 0;
    private volatile int tokenExpiresInSeconds = 3600;
    private final Map<String, Integer> tokenCallCountByClientId = new ConcurrentHashMap<>();

    @AfterEach
    void tearDown() {
        if (server != null) {
            server.stop(0);
        }
        SecurityContextHolder.clearContext();
        MDC.clear();
    }

    private record RecordedRequest(String method, Map<String, List<String>> headers, Map<String, String> form) {
        RecordedRequest(String method, Map<String, List<String>> headers) {
            this(method, headers, Map.of());
        }
    }

    private record CannedResponse(int status, String contentType, byte[] body) {
        static CannedResponse ok() {
            return new CannedResponse(200, "text/plain", "ok".getBytes(StandardCharsets.UTF_8));
        }

        static CannedResponse status(int status) {
            return new CannedResponse(status, "text/plain", "".getBytes(StandardCharsets.UTF_8));
        }
    }

    private void plan(String path, CannedResponse... responses) {
        planned.put(path, new ArrayDeque<>(List.of(responses)));
    }

    private List<RecordedRequest> requestsTo(String path) {
        return received.getOrDefault(path, List.of());
    }

    private String startServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(Executors.newCachedThreadPool());
        for (String path : List.of("/ping", "/create", "/fail", "/slow")) {
            server.createContext(path, dispatcher(path));
        }
        server.createContext("/token", tokenEndpointDispatcher());
        server.start();
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    /**
     * A minimal RFC 6749 §4.4 token endpoint - real HTTP, real Basic-auth
     * parsing, real JSON body - used by the client_credentials wire
     * tests. A pre-planned response (via {@link #plan}, same mechanism as
     * every other path) takes priority when set, for the error-path tests;
     * otherwise it derives the access token from the calling client-id (so
     * two different registrations provably never receive the same token
     * value, without depending on call ordering) and mints one distinct
     * value per call to that client-id, so reuse vs. renewal is directly
     * observable from the token value itself.
     */
    private HttpHandler tokenEndpointDispatcher() {
        return (HttpExchange exchange) -> {
            Map<String, List<String>> headers = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            exchange.getRequestHeaders().forEach(headers::put);
            Map<String, String> form = parseForm(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            received.computeIfAbsent("/token", k -> new CopyOnWriteArrayList<>())
                    .add(new RecordedRequest(exchange.getRequestMethod(), headers, form));

            Deque<CannedResponse> queue = planned.get("/token");
            if (queue != null && !queue.isEmpty()) {
                CannedResponse response = queue.size() > 1 ? queue.poll() : queue.peek();
                exchange.getResponseHeaders().add("Content-Type", response.contentType());
                exchange.sendResponseHeaders(response.status(), response.body().length);
                try (OutputStream body = exchange.getResponseBody()) {
                    body.write(response.body());
                }
                return;
            }

            String accessToken;
            if (TOKEN_EXCHANGE_GRANT.equals(form.get("grant_type"))) {
                // RFC 8693: the issued token is derived from the subject, so a token
                // exchanged for user A can never be mistaken for user B's.
                String subject = form.get("subject_token");
                int callNumber = tokenCallCountByClientId.merge("exchange:" + subject, 1, Integer::sum);
                accessToken = "exchanged-" + subject + "-call-" + callNumber;
            } else {
                String clientId = clientIdFromBasicAuth(headers);
                int callNumber = tokenCallCountByClientId.merge(clientId, 1, Integer::sum);
                accessToken = "token-for-" + clientId + "-call-" + callNumber;
            }

            String json = ("{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":%d}")
                    .formatted(accessToken, tokenExpiresInSeconds);
            byte[] body = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(body);
            }
        };
    }

    private static final String TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange";

    private static Map<String, String> parseForm(String body) {
        Map<String, String> form = new HashMap<>();
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                form.put(java.net.URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8),
                        java.net.URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8));
            }
        }
        return form;
    }

    private static String clientIdFromBasicAuth(Map<String, List<String>> headers) {
        String authHeader = headers.getOrDefault("Authorization", List.of()).stream()
                .findFirst().orElse("");
        if (!authHeader.startsWith("Basic ")) {
            return "unknown";
        }
        String decoded = new String(Base64.getDecoder().decode(authHeader.substring("Basic ".length())),
                StandardCharsets.UTF_8);
        int colon = decoded.indexOf(':');
        return colon >= 0 ? decoded.substring(0, colon) : decoded;
    }

    private HttpHandler dispatcher(String path) {
        return (HttpExchange exchange) -> {
            Map<String, List<String>> headers = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            exchange.getRequestHeaders().forEach(headers::put);
            received.computeIfAbsent(path, k -> new CopyOnWriteArrayList<>())
                    .add(new RecordedRequest(exchange.getRequestMethod(), headers));
            exchange.getRequestBody().readAllBytes();

            if ("/slow".equals(path) && slowResponseDelayMillis > 0) {
                try {
                    Thread.sleep(slowResponseDelayMillis);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }

            Deque<CannedResponse> queue = planned.get(path);
            CannedResponse response = (queue == null || queue.isEmpty())
                    ? CannedResponse.ok()
                    : (queue.size() > 1 ? queue.poll() : queue.peek());

            exchange.getResponseHeaders().add("Content-Type", response.contentType());
            exchange.sendResponseHeaders(response.status(), response.body().length);
            try (OutputStream body = exchange.getResponseBody()) {
                body.write(response.body());
            }
        };
    }

    private ApplicationContextRunner baseRunner(String baseUrl) {
        return new ApplicationContextRunner()
                .withUserConfiguration(WirePackageMarker.class)
                .withConfiguration(AutoConfigurations.of(
                        ServiceClientAutoConfiguration.class, RestClientAutoConfiguration.class,
                        HttpServiceClientAutoConfiguration.class, HttpServiceClientPropertiesAutoConfiguration.class, JacksonAutoConfiguration.class,
                        SslAutoConfiguration.class))
                .withPropertyValues("spring.http.serviceclient.wireClient.base-url=" + baseUrl);
    }

    /**
     * Adds {@link WireClientCreds} (group {@code wireClientCreds}, two
     * {@code @ClientRegistrationId}-annotated methods - see its Javadoc) and
     * Boot's own native {@link OAuth2ClientAutoConfiguration} - the source
     * of the {@code ClientRegistrationRepository}/{@code OAuth2AuthorizedClientService}
     * beans {@code ServiceClientAutoConfiguration}'s own client_credentials
     * manager needs - on top of {@link #baseRunner}. The
     * "keycloak" registration used by {@code pingAsClient()} is left to each
     * test to configure via {@code withPropertyValues}, since some tests
     * need it as {@code client_credentials} and others (none in this class)
     * could need a different shape entirely.
     */
    private ApplicationContextRunner m2mRunner(String baseUrl) {
        return baseRunner(baseUrl)
                .withUserConfiguration(WireClientCredsPackageMarker.class)
                .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class))
                .withPropertyValues("spring.http.serviceclient.wireClientCreds.base-url=" + baseUrl);
    }

    private static String[] clientCredentialsRegistrationProperties(
            String registrationId, String clientId, String tokenUri) {
        String prefix = "spring.security.oauth2.client.registration." + registrationId + ".";
        return new String[] {
                prefix + "client-id=" + clientId,
                prefix + "client-secret=" + clientId + "-secret",
                prefix + "authorization-grant-type=client_credentials",
                prefix + "provider=" + registrationId,
                "spring.security.oauth2.client.provider." + registrationId + ".token-uri=" + tokenUri
        };
    }

    // ------------------------------------------------------------------
    // Token relay - resource server mode
    // ------------------------------------------------------------------

    @Test
    void givenResourceServerMode_whenCalling_thenIncomingJwtIsRelayedAsBearer() throws Exception {
        String baseUrl = startServer();
        Jwt jwt = Jwt.withTokenValue("incoming-user-jwt")
                .header("alg", "none").claim("sub", "user-1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));

        baseRunner(baseUrl).run(context -> {
            WireClient client = context.getBean(WireClient.class);
            client.ping();
        });

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer incoming-user-jwt");
    }

    @Test
    void givenResourceServerModeWithOpaqueToken_whenCalling_thenIncomingBearerTokenIsRelayed() throws Exception {
        String baseUrl = startServer();
        org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal principal =
                new org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal(
                        "user-1", Map.of("sub", "user-1"), List.of());
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "incoming-opaque-token", Instant.now(), Instant.now().plusSeconds(60));
        SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication(
                        principal, accessToken, List.of()));

        baseRunner(baseUrl).run(context -> {
            WireClient client = context.getBean(WireClient.class);
            client.ping();
        });

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer incoming-opaque-token");
    }

    @Test
    void givenNoTokenRelayAnnotatedMethod_whenCalling_thenNoAuthorizationHeaderIsSent() throws Exception {
        String baseUrl = startServer();
        Jwt jwt = Jwt.withTokenValue("incoming-user-jwt")
                .header("alg", "none").claim("sub", "user-1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));

        baseRunner(baseUrl).run(context -> {
            WireClient client = context.getBean(WireClient.class);
            client.noTokenRelayPing();
        });

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().containsKey("Authorization")).isFalse();
    }

    // ------------------------------------------------------------------
    // Token relay - client mode
    // ------------------------------------------------------------------

    @Configuration(proxyBeanMethods = false)
    static class FixedClientTokenConfiguration {
        @Bean
        OAuth2AuthorizedClientManager authorizedClientManager() {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER, "client-credentials-token", Instant.now(), Instant.now().plusSeconds(60));
            return new OAuth2AuthorizedClientManager() {
                @Override
                public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
                    return new OAuth2AuthorizedClient(
                            org.springframework.security.oauth2.client.registration.ClientRegistration
                                    .withRegistrationId("keycloak")
                                    .clientId("test").tokenUri("http://localhost/token")
                                    .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.CLIENT_CREDENTIALS)
                                    .build(),
                            "principal",
                            accessToken);
                }
            };
        }
    }

    @Test
    void givenClientMode_whenCalling_thenTokenFromAuthorizedClientManagerIsPresented() throws Exception {
        String baseUrl = startServer();

        // Declares a registration explicitly (WireClientCreds) - a
        // manager being merely present is not enough, by design: it
        // must be declared per call via @ClientRegistrationId, or the
        // caller must be a BFF principal (a separate test covers that path).
        new ApplicationContextRunner()
                .withUserConfiguration(
                        com.trust.restclient.fixture.wire.WireClientCredsPackageMarker.class,
                        FixedClientTokenConfiguration.class)
                .withConfiguration(AutoConfigurations.of(
                        ServiceClientAutoConfiguration.class, RestClientAutoConfiguration.class,
                        HttpServiceClientAutoConfiguration.class, HttpServiceClientPropertiesAutoConfiguration.class,
                        JacksonAutoConfiguration.class, SslAutoConfiguration.class))
                .withPropertyValues("spring.http.serviceclient.wireClientCreds.base-url=" + baseUrl)
                .run(context -> {
                    com.trust.restclient.fixture.wire.WireClientCreds client =
                            context.getBean(com.trust.restclient.fixture.wire.WireClientCreds.class);
                    client.pingAsClient();
                });

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer client-credentials-token");
    }

    private static String[] tokenExchangeRegistrationProperties(
            String registrationId, String clientId, String tokenUri) {
        String prefix = "spring.security.oauth2.client.registration." + registrationId + ".";
        return new String[] {
                prefix + "client-id=" + clientId,
                prefix + "client-secret=" + clientId + "-secret",
                prefix + "authorization-grant-type=" + TOKEN_EXCHANGE_GRANT,
                prefix + "provider=" + registrationId,
                "spring.security.oauth2.client.provider." + registrationId + ".token-uri=" + tokenUri
        };
    }

    private static void authenticateWithJwt(String tokenValue, String subject) {
        Jwt jwt = Jwt.withTokenValue(tokenValue)
                .header("alg", "none").claim("sub", subject)
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        // The authorities constructor marks it authenticated, as a real resource server's converter does.
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt, List.of()));
    }

    // ------------------------------------------------------------------
    // Token relay - autonomous client_credentials
    //
    // Unlike the fixed-token test above, these exercise Trust's own
    // auto-configured OAuth2AuthorizedClientManager end-to-end against a
    // real local token endpoint (RFC 6749 §4.4) - no hand-rolled manager.
    // ------------------------------------------------------------------

    @Test
    void givenClientRegistrationId_whenCalling_thenTechnicalTokenIsObtainedAndPresented() throws Exception {
        String baseUrl = startServer();

        m2mRunner(baseUrl)
                .withPropertyValues(clientCredentialsRegistrationProperties("keycloak", "document-inventory", baseUrl + "/token"))
                .run(context -> context.getBean(WireClientCreds.class).pingAsClient());

        assertThat(requestsTo("/token")).hasSize(1);
        String authHeaderAtTokenEndpoint = requestsTo("/token").get(0).headers().get("Authorization").get(0);
        assertThat(authHeaderAtTokenEndpoint).startsWith("Basic ");
        assertThat(new String(Base64.getDecoder().decode(authHeaderAtTokenEndpoint.substring("Basic ".length())),
                StandardCharsets.UTF_8)).isEqualTo("document-inventory:document-inventory-secret");

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer token-for-document-inventory-call-1");
    }

    @Test
    void givenTwoConsecutiveCalls_whenTokenStillValid_thenTheTokenEndpointIsCalledOnlyOnce() throws Exception {
        String baseUrl = startServer();

        m2mRunner(baseUrl)
                .withPropertyValues(clientCredentialsRegistrationProperties("keycloak", "document-inventory", baseUrl + "/token"))
                .run(context -> {
                    WireClientCreds client = context.getBean(WireClientCreds.class);
                    client.pingAsClient();
                    client.pingAsClient();
                });

        assertThat(requestsTo("/token")).hasSize(1);
        assertThat(requestsTo("/ping")).hasSize(2);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .isEqualTo(requestsTo("/ping").get(1).headers().get("Authorization"));
    }

    @Test
    void givenTheTokenHasExpired_whenCallingAgain_thenANewTokenIsObtained() throws Exception {
        String baseUrl = startServer();
        tokenExpiresInSeconds = 1;

        m2mRunner(baseUrl)
                .withPropertyValues(clientCredentialsRegistrationProperties("keycloak", "document-inventory", baseUrl + "/token"))
                .run(context -> {
                    WireClientCreds client = context.getBean(WireClientCreds.class);
                    client.pingAsClient();
                    Thread.sleep(1500);
                    client.pingAsClient();
                });

        assertThat(requestsTo("/token")).hasSize(2);
        List<String> firstCallAuth = requestsTo("/ping").get(0).headers().get("Authorization");
        List<String> secondCallAuth = requestsTo("/ping").get(1).headers().get("Authorization");
        assertThat(firstCallAuth).isNotEqualTo(secondCallAuth);
    }

    @Test
    void givenTwoDifferentClientRegistrationIds_whenCalling_thenTheyNeverShareAToken() throws Exception {
        String baseUrl = startServer();

        baseRunner(baseUrl)
                .withUserConfiguration(
                        com.trust.restclient.fixture.wire.WireClientTwoRegistrationsPackageMarker.class)
                .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class))
                .withPropertyValues("spring.http.serviceclient.wireClientTwoRegistrations.base-url=" + baseUrl)
                .withPropertyValues(clientCredentialsRegistrationProperties("keycloak", "document-inventory", baseUrl + "/token"))
                .withPropertyValues(clientCredentialsRegistrationProperties("other-m2m", "billing-service", baseUrl + "/token"))
                .run(context -> {
                    com.trust.restclient.fixture.wire.WireClientTwoRegistrations client =
                            context.getBean(com.trust.restclient.fixture.wire.WireClientTwoRegistrations.class);
                    client.pingAsClient();
                    client.createAsClient();
                });

        assertThat(requestsTo("/token")).hasSize(2);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer token-for-document-inventory-call-1");
        assertThat(requestsTo("/create").get(0).headers().get("Authorization"))
                .containsExactly("Bearer token-for-billing-service-call-1");
    }

    @Test
    void givenAnIncomingUserToken_whenCallingWithClientRegistrationId_thenTheTechnicalTokenWinsNeverTheUsersOwn()
            throws Exception {
        String baseUrl = startServer();
        Jwt jwt = Jwt.withTokenValue("incoming-user-jwt")
                .header("alg", "none").claim("sub", "user-1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));

        m2mRunner(baseUrl)
                .withPropertyValues(clientCredentialsRegistrationProperties("keycloak", "document-inventory", baseUrl + "/token"))
                .run(context -> context.getBean(WireClientCreds.class).pingAsClient());

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .as("the incoming user's JWT must never be sent for a @ClientRegistrationId call")
                .containsExactly("Bearer token-for-document-inventory-call-1");
    }

    /**
     * Same call as above, minus any {@link SecurityContextHolder} entry at
     * all - simulates a batch/scheduled task/listener with no incoming
     * request. Must succeed identically: the technical principal never
     * touches the security context.
     */
    @Test
    void givenNoSecurityContextAtAll_whenCallingWithClientRegistrationId_thenItStillSucceeds() throws Exception {
        String baseUrl = startServer();
        SecurityContextHolder.clearContext();

        m2mRunner(baseUrl)
                .withPropertyValues(clientCredentialsRegistrationProperties("keycloak", "document-inventory", baseUrl + "/token"))
                .run(context -> context.getBean(WireClientCreds.class).pingAsClient());

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer token-for-document-inventory-call-1");
    }

    @Test
    void givenTheTokenEndpointFails_whenCalling_thenTheTargetApiIsNeverCalled() throws Exception {
        String baseUrl = startServer();
        plan("/token", CannedResponse.status(400));

        // token-acquisition-retry is enabled by default (RetryingOAuth2AuthorizedClientManager,
        // 3 attempts) - disabled here so this test isolates a single concern
        // (the target API is never reached) instead of also asserting a
        // retry count that belongs to a different test.
        m2mRunner(baseUrl)
                .withPropertyValues(clientCredentialsRegistrationProperties("keycloak", "document-inventory", baseUrl + "/token"))
                .withPropertyValues("trust.rest-client.token-acquisition-retry.enabled=false")
                .run(context -> assertThatThrownBy(() -> context.getBean(WireClientCreds.class).pingAsClient()));

        assertThat(requestsTo("/token")).hasSize(1);
        assertThat(requestsTo("/ping")).as("the target API must never be reached without a technical token").isEmpty();
    }

    /**
     * Non-regression: a client_credentials registration being configured
     * elsewhere in the application must not change what an unannotated call
     * does - it still relays the current user's own token.
     */
    @Test
    void givenAClientCredentialsRegistrationConfigured_whenCallingAnUnannotatedMethod_thenUserTokenRelayIsUnchanged()
            throws Exception {
        String baseUrl = startServer();
        Jwt jwt = Jwt.withTokenValue("incoming-user-jwt")
                .header("alg", "none").claim("sub", "user-1")
                .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(60)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));

        m2mRunner(baseUrl)
                .withPropertyValues(clientCredentialsRegistrationProperties("keycloak", "document-inventory", baseUrl + "/token"))
                .run(context -> context.getBean(WireClient.class).ping());

        assertThat(requestsTo("/token")).as("an unannotated call must never touch the token endpoint").isEmpty();
        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer incoming-user-jwt");
    }

    // ------------------------------------------------------------------
    // Token exchange (RFC 8693) - on behalf of the incoming user
    //
    // Same fixture as client_credentials (WireClientCreds, registration
    // "keycloak"), declared as a token-exchange registration instead.
    // ------------------------------------------------------------------

    @Test
    void givenATokenExchangeRegistrationAndAJwtUser_whenCalling_thenTheExchangedTokenIsPresentedNeverTheIncomingOne()
            throws Exception {
        String baseUrl = startServer();
        authenticateWithJwt("incoming-user-jwt", "user-1");

        m2mRunner(baseUrl)
                .withPropertyValues(tokenExchangeRegistrationProperties("keycloak", "document-gateway", baseUrl + "/token"))
                .run(context -> context.getBean(WireClientCreds.class).pingAsClient());

        assertThat(requestsTo("/token")).hasSize(1);
        RecordedRequest exchange = requestsTo("/token").get(0);
        assertThat(exchange.form())
                .containsEntry("grant_type", TOKEN_EXCHANGE_GRANT)
                .containsEntry("subject_token", "incoming-user-jwt")
                .as("Keycloak's standard token exchange only accepts the access_token subject type")
                .containsEntry("subject_token_type", "urn:ietf:params:oauth:token-type:access_token");
        assertThat(new String(Base64.getDecoder().decode(
                exchange.headers().get("Authorization").get(0).substring("Basic ".length())), StandardCharsets.UTF_8))
                .as("the exchanging application authenticates itself at the token endpoint")
                .isEqualTo("document-gateway:document-gateway-secret");

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer exchanged-incoming-user-jwt-call-1");
    }

    @Test
    void givenATokenExchangeRegistrationAndAnOpaqueTokenUser_whenCalling_thenTheOpaqueTokenIsExchanged()
            throws Exception {
        String baseUrl = startServer();
        org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal principal =
                new org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal(
                        "user-1", Map.of("sub", "user-1"), List.of());
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "incoming-opaque-token", Instant.now(), Instant.now().plusSeconds(60));
        SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication(
                        principal, accessToken, List.of()));

        m2mRunner(baseUrl)
                .withPropertyValues(tokenExchangeRegistrationProperties("keycloak", "document-gateway", baseUrl + "/token"))
                .run(context -> context.getBean(WireClientCreds.class).pingAsClient());

        assertThat(requestsTo("/token")).hasSize(1);
        assertThat(requestsTo("/token").get(0).form()).containsEntry("subject_token", "incoming-opaque-token");
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer exchanged-incoming-opaque-token-call-1");
    }

    /**
     * The exchanged token is cached per user: reused for the same user, never
     * shared with another one.
     */
    @Test
    void givenTwoUsers_whenEachCallsTwice_thenEachGetsTheirOwnExchangedTokenExchangedOnlyOnce() throws Exception {
        String baseUrl = startServer();

        m2mRunner(baseUrl)
                .withPropertyValues(tokenExchangeRegistrationProperties("keycloak", "document-gateway", baseUrl + "/token"))
                .run(context -> {
                    WireClientCreds client = context.getBean(WireClientCreds.class);
                    authenticateWithJwt("jwt-of-alice", "alice");
                    client.pingAsClient();
                    authenticateWithJwt("jwt-of-bob", "bob");
                    client.pingAsClient();
                    authenticateWithJwt("jwt-of-alice", "alice");
                    client.pingAsClient();
                });

        assertThat(requestsTo("/token")).as("one exchange per user, the second alice call reuses hers").hasSize(2);
        assertThat(requestsTo("/ping")).extracting(request -> request.headers().get("Authorization").get(0))
                .containsExactly(
                        "Bearer exchanged-jwt-of-alice-call-1",
                        "Bearer exchanged-jwt-of-bob-call-1",
                        "Bearer exchanged-jwt-of-alice-call-1");
    }

    @Test
    void givenATokenExchangeRegistrationAndNoUserAtAll_whenCalling_thenItFailsBeforeAnythingIsSent() throws Exception {
        String baseUrl = startServer();
        SecurityContextHolder.clearContext();

        m2mRunner(baseUrl)
                .withPropertyValues(tokenExchangeRegistrationProperties("keycloak", "document-gateway", baseUrl + "/token"))
                .run(context -> assertThatThrownBy(() -> context.getBean(WireClientCreds.class).pingAsClient())
                        .isInstanceOf(com.trust.restclient.tokenrelay.TokenExchangeSubjectException.class)
                        .hasMessageContaining("keycloak"));

        assertThat(requestsTo("/token")).isEmpty();
        assertThat(requestsTo("/ping")).as("never sent unauthenticated, never as the application").isEmpty();
    }

    @Test
    void givenATokenExchangeRegistrationAndAnAnonymousUser_whenCalling_thenItFailsBeforeAnythingIsSent() throws Exception {
        String baseUrl = startServer();
        SecurityContextHolder.getContext().setAuthentication(
                new org.springframework.security.authentication.AnonymousAuthenticationToken(
                        "key", "anonymousUser", List.of(new SimpleGrantedAuthority("ROLE_ANONYMOUS"))));

        m2mRunner(baseUrl)
                .withPropertyValues(tokenExchangeRegistrationProperties("keycloak", "document-gateway", baseUrl + "/token"))
                .run(context -> assertThatThrownBy(() -> context.getBean(WireClientCreds.class).pingAsClient())
                        .isInstanceOf(com.trust.restclient.tokenrelay.TokenExchangeSubjectException.class));

        assertThat(requestsTo("/token")).isEmpty();
        assertThat(requestsTo("/ping")).isEmpty();
    }

    @Test
    void givenATokenExchangeRegistrationAndAUserWithoutABearerToken_whenCalling_thenItFailsBeforeTheTargetIsCalled()
            throws Exception {
        String baseUrl = startServer();
        SecurityContextHolder.getContext().setAuthentication(
                org.springframework.security.authentication.UsernamePasswordAuthenticationToken.authenticated(
                        "alice", "password", List.of()));

        m2mRunner(baseUrl)
                .withPropertyValues(tokenExchangeRegistrationProperties("keycloak", "document-gateway", baseUrl + "/token"))
                .run(context -> assertThatThrownBy(() -> context.getBean(WireClientCreds.class).pingAsClient())
                        .isInstanceOf(com.trust.restclient.tokenrelay.TokenExchangeSubjectException.class)
                        .hasMessageContaining("UsernamePasswordAuthenticationToken"));

        assertThat(requestsTo("/token")).isEmpty();
        assertThat(requestsTo("/ping")).isEmpty();
    }

    @Test
    void givenTheTokenExchangeIsRefused_whenCalling_thenTheTargetApiIsNeverCalled() throws Exception {
        String baseUrl = startServer();
        authenticateWithJwt("incoming-user-jwt", "user-1");
        plan("/token", new CannedResponse(400, "application/json",
                "{\"error\":\"invalid_request\"}".getBytes(StandardCharsets.UTF_8)));

        m2mRunner(baseUrl)
                .withPropertyValues(tokenExchangeRegistrationProperties("keycloak", "document-gateway", baseUrl + "/token"))
                .withPropertyValues("trust.rest-client.token-acquisition-retry.enabled=false")
                .run(context -> assertThatThrownBy(() -> context.getBean(WireClientCreds.class).pingAsClient()));

        assertThat(requestsTo("/token")).hasSize(1);
        assertThat(requestsTo("/ping")).as("never falls back to relaying the incoming token").isEmpty();
    }

    // ------------------------------------------------------------------
    // Token relay - BFF mode (unannotated interface, user's session token)
    // ------------------------------------------------------------------

    @Configuration(proxyBeanMethods = false)
    static class FixedBffTokenConfiguration {
        @Bean
        OAuth2AuthorizedClientManager authorizedClientManager() {
            OAuth2AccessToken accessToken = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER, "bff-session-token", Instant.now(), Instant.now().plusSeconds(60));
            return new OAuth2AuthorizedClientManager() {
                @Override
                public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
                    return new OAuth2AuthorizedClient(
                            org.springframework.security.oauth2.client.registration.ClientRegistration
                                    .withRegistrationId(authorizeRequest.getClientRegistrationId())
                                    .clientId("test").tokenUri("http://localhost/token")
                                    .authorizationGrantType(org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                                    .redirectUri("http://localhost/login/oauth2/code/keycloak")
                                    .authorizationUri("http://localhost/authorize")
                                    .build(),
                            "principal",
                            accessToken);
                }
            };
        }
    }

    @Test
    void givenBffModeWithNoAnnotation_whenCalling_thenUserSessionTokenIsCarried() throws Exception {
        String baseUrl = startServer();

        // No @ClientRegistrationId on WireClient, and no incoming JWT (not a
        // resource server): ResourceServerTokenRelayInterceptor abstains
        // (nothing of type JwtAuthenticationToken), and TrustClientRegistrationIdResolver
        // falls through to the BFF path - the registration the user
        // authenticated with.
        DefaultOAuth2User principal = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("ROLE_USER")), Map.of("sub", "user-1"), "sub");
        OAuth2AuthenticationToken userAuthentication =
                new OAuth2AuthenticationToken(principal, principal.getAuthorities(), "keycloak");
        SecurityContextHolder.getContext().setAuthentication(userAuthentication);

        baseRunner(baseUrl)
                .withUserConfiguration(FixedBffTokenConfiguration.class)
                .run(context -> {
                    WireClient client = context.getBean(WireClient.class);
                    client.ping();
                });

        assertThat(requestsTo("/ping")).hasSize(1);
        assertThat(requestsTo("/ping").get(0).headers().get("Authorization"))
                .containsExactly("Bearer bff-session-token");
    }

    // ------------------------------------------------------------------
    // Correlation
    // ------------------------------------------------------------------

    @Test
    void givenCorrelationIdInMdc_whenCalling_thenItIsPropagatedOnTheOutgoingRequest() throws Exception {
        String baseUrl = startServer();
        MDC.put("correlationId", "corr-abc-123");

        baseRunner(baseUrl).run(context -> {
            WireClient client = context.getBean(WireClient.class);
            client.ping();
        });

        assertThat(requestsTo("/ping").get(0).headers().get("X-Correlation-ID"))
                .containsExactly("corr-abc-123");
    }

    @Test
    void givenNoIncomingRequestAndNoMdcEntry_whenCallingRepeatedly_thenEachCallGetsItsOwnGeneratedCorrelationId()
            throws Exception {
        String baseUrl = startServer();
        // A batch has no incoming request, so nothing ever
        // populates MDC for it - the interceptor must generate a fallback id
        // per call rather than propagate nothing.
        assertThat(MDC.get("correlationId")).isNull();

        baseRunner(baseUrl).run(context -> {
            WireClient client = context.getBean(WireClient.class);
            client.ping();
            client.ping();
        });

        assertThat(requestsTo("/ping")).hasSize(2);
        String first = requestsTo("/ping").get(0).headers().get("X-Correlation-ID").get(0);
        String second = requestsTo("/ping").get(1).headers().get("X-Correlation-ID").get(0);
        assertThat(first).isNotBlank();
        assertThat(second).isNotBlank();
        assertThat(first).isNotEqualTo(second);
        assertThat(MDC.get("correlationId"))
                .as("MDC must be restored to its prior (empty) state after each call")
                .isNull();
    }

    @Test
    void givenApplicationPostsCorrelationIdInMdcForABatchRun_whenCallingMultipleTimes_thenItIsRespectedForEachCall()
            throws Exception {
        String baseUrl = startServer();
        // An application correlating an entire batch run poses the id itself,
        // once, at the start - it must never be overwritten by the fallback.
        MDC.put("correlationId", "batch-run-42");

        baseRunner(baseUrl).run(context -> {
            WireClient client = context.getBean(WireClient.class);
            client.ping();
            client.ping();
        });

        assertThat(requestsTo("/ping")).hasSize(2);
        assertThat(requestsTo("/ping").get(0).headers().get("X-Correlation-ID")).containsExactly("batch-run-42");
        assertThat(requestsTo("/ping").get(1).headers().get("X-Correlation-ID")).containsExactly("batch-run-42");
        assertThat(MDC.get("correlationId")).isEqualTo("batch-run-42");
    }

    // ------------------------------------------------------------------
    // Retry
    // ------------------------------------------------------------------

    @Test
    void givenTransientFailuresOnIdempotentMethod_whenCalling_thenItIsRetriedUntilSuccess() throws Exception {
        String baseUrl = startServer();
        plan("/ping", CannedResponse.status(503), CannedResponse.status(503), CannedResponse.ok());

        baseRunner(baseUrl)
                .withPropertyValues("trust.rest-client.retry.wait-duration=5ms")
                .run(context -> {
                    WireClient client = context.getBean(WireClient.class);
                    String result = client.ping();
                    assertThat(result).isEqualTo("ok");
                });

        assertThat(requestsTo("/ping")).hasSize(3);
    }

    @Test
    void givenTransientFailureOnPost_whenCalling_thenItIsNeverRetried() throws Exception {
        String baseUrl = startServer();
        plan("/create", CannedResponse.status(503));

        baseRunner(baseUrl)
                .withPropertyValues("trust.rest-client.retry.wait-duration=5ms")
                .run(context -> {
                    WireClient client = context.getBean(WireClient.class);
                    assertThatThrownBy(client::create);
                });

        assertThat(requestsTo("/create")).hasSize(1);
    }

    @Test
    void givenNoRetryAnnotatedMethod_whenTransientFailureOccurs_thenItIsNeverRetried() throws Exception {
        String baseUrl = startServer();
        plan("/ping", CannedResponse.status(503));

        baseRunner(baseUrl)
                .withPropertyValues("trust.rest-client.retry.wait-duration=5ms")
                .run(context -> {
                    WireClient client = context.getBean(WireClient.class);
                    assertThatThrownBy(client::noRetryPing);
                });

        assertThat(requestsTo("/ping")).hasSize(1);
    }

    // ------------------------------------------------------------------
    // Circuit breaker
    // ------------------------------------------------------------------

    @Test
    void givenRepeatedFailures_whenThresholdExceeded_thenCircuitOpensAndStopsCallingTheServer() throws Exception {
        String baseUrl = startServer();
        plan("/ping", CannedResponse.status(500), CannedResponse.status(500));

        baseRunner(baseUrl)
                .withPropertyValues(
                        "trust.rest-client.retry.enabled=false",
                        "trust.rest-client.circuit-breaker.sliding-window-size=2",
                        "trust.rest-client.circuit-breaker.minimum-number-of-calls=2")
                .run(context -> {
                    WireClient client = context.getBean(WireClient.class);
                    assertThatThrownBy(client::ping);
                    assertThatThrownBy(client::ping);
                    assertThat(requestsTo("/ping")).hasSize(2);

                    // Circuit should now be open: a third call must not reach the server at all.
                    assertThatThrownBy(client::ping).isInstanceOf(CallNotPermittedException.class);
                    assertThat(requestsTo("/ping")).hasSize(2);
                });
    }

    // ------------------------------------------------------------------
    // Problem Details
    // ------------------------------------------------------------------

    @Test
    void givenErrorResponseWithProblemDetailsBody_whenCalling_thenExceptionExposesTheParsedProblemDetail() throws Exception {
        String baseUrl = startServer();
        String problemJson = "{\"type\":\"about:blank\",\"title\":\"Invalid\",\"status\":422,"
                + "\"detail\":\"bad input\",\"instance\":\"/fail\"}";
        planned.put("/fail", new ArrayDeque<>(List.of(
                new CannedResponse(422, "application/problem+json", problemJson.getBytes(StandardCharsets.UTF_8)))));

        baseRunner(baseUrl).run(context -> {
            WireClient client = context.getBean(WireClient.class);
            assertThatThrownBy(client::fail)
                    .isInstanceOf(ServiceClientResponseException.class)
                    .satisfies(ex -> {
                        ServiceClientResponseException sce = (ServiceClientResponseException) ex;
                        assertThat(sce.getStatusCode().value()).isEqualTo(422);
                        assertThat(sce.getProblemDetail()).isPresent();
                        assertThat(sce.getProblemDetail().get().getDetail()).isEqualTo("bad input");
                    });
        });
    }

    // ------------------------------------------------------------------
    // Timeouts
    // ------------------------------------------------------------------

    @Test
    void givenServerSlowerThanReadTimeout_whenCalling_thenCallFailsPromptlyRatherThanHanging() throws Exception {
        String baseUrl = startServer();
        slowResponseDelayMillis = 2000;

        baseRunner(baseUrl)
                .withPropertyValues(
                        "spring.http.serviceclient.wireClient.read-timeout=150ms",
                        "trust.rest-client.retry.enabled=false")
                .run(context -> {
                    WireClient client = context.getBean(WireClient.class);
                    long start = System.currentTimeMillis();
                    assertThatThrownBy(client::slow);
                    long elapsed = System.currentTimeMillis() - start;
                    assertThat(elapsed).isLessThan(1000L);
                });
    }

    // ------------------------------------------------------------------
    // Mutual TLS
    // ------------------------------------------------------------------

    private static final char[] STORE_PASSWORD = "changeit".toCharArray();

    @Test
    void givenSslBundleConfigured_whenCallingAServerRequiringAClientCertificate_thenItPresentsOne(
            @org.junit.jupiter.api.io.TempDir Path tempDir) throws Exception {
        generateCertificates(tempDir);
        SSLContext serverSslContext = buildServerSslContext(tempDir);
        SslBundle clientBundle = buildClientSslBundle(tempDir);

        HttpsServer httpsServer = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(serverSslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters sslParameters = getSSLContext().getDefaultSSLParameters();
                sslParameters.setNeedClientAuth(true);
                params.setSSLParameters(sslParameters);
            }
        });
        List<String> clientCns = new ArrayList<>();
        httpsServer.createContext("/ping", exchange -> {
            byte[] responseBytes = "pong".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, responseBytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(responseBytes);
            }
        });
        httpsServer.start();
        try {
            String baseUrl = "https://127.0.0.1:" + httpsServer.getAddress().getPort();

            new ApplicationContextRunner()
                    .withUserConfiguration(WirePackageMarker.class)
                    .withConfiguration(AutoConfigurations.of(
                            ServiceClientAutoConfiguration.class, RestClientAutoConfiguration.class,
                            HttpServiceClientAutoConfiguration.class, HttpServiceClientPropertiesAutoConfiguration.class, JacksonAutoConfiguration.class))
                    .withBean(SslBundles.class, () -> {
                        DefaultSslBundleRegistry registry = new DefaultSslBundleRegistry();
                        registry.registerBundle("wire-mtls", clientBundle);
                        return registry;
                    })
                    .withPropertyValues(
                            "spring.http.serviceclient.wireClient.base-url=" + baseUrl,
                            "spring.http.serviceclient.wireClient.ssl.bundle=wire-mtls")
                    .run(context -> {
                        WireClient client = context.getBean(WireClient.class);
                        assertThat(client.ping()).isEqualTo("pong");
                    });
        } finally {
            httpsServer.stop(0);
        }
    }

    private static void generateCertificates(Path dir) throws Exception {
        runKeytool(dir, "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048", "-validity", "30",
                "-keystore", p(dir, "server.p12"), "-storetype", "PKCS12",
                "-storepass", "changeit", "-keypass", "changeit",
                "-dname", "CN=localhost", "-ext", "SAN=dns:localhost,ip:127.0.0.1");
        runKeytool(dir, "-exportcert", "-alias", "server", "-keystore", p(dir, "server.p12"),
                "-storetype", "PKCS12", "-storepass", "changeit", "-file", p(dir, "server.cer"));
        runKeytool(dir, "-genkeypair", "-alias", "client", "-keyalg", "RSA", "-keysize", "2048", "-validity", "30",
                "-keystore", p(dir, "client.p12"), "-storetype", "PKCS12",
                "-storepass", "changeit", "-keypass", "changeit", "-dname", "CN=trust-client");
        runKeytool(dir, "-exportcert", "-alias", "client", "-keystore", p(dir, "client.p12"),
                "-storetype", "PKCS12", "-storepass", "changeit", "-file", p(dir, "client.cer"));
        runKeytool(dir, "-importcert", "-alias", "server", "-file", p(dir, "server.cer"),
                "-keystore", p(dir, "client-truststore.p12"), "-storetype", "PKCS12",
                "-storepass", "changeit", "-noprompt");
        runKeytool(dir, "-importcert", "-alias", "client", "-file", p(dir, "client.cer"),
                "-keystore", p(dir, "server-truststore.p12"), "-storetype", "PKCS12",
                "-storepass", "changeit", "-noprompt");
    }

    private static String p(Path dir, String fileName) {
        return dir.resolve(fileName).toString();
    }

    private static void runKeytool(Path dir, String... args) throws IOException, InterruptedException {
        List<String> command = new ArrayList<>();
        command.add(System.getProperty("java.home") + "/bin/keytool");
        command.addAll(List.of(args));
        Process process = new ProcessBuilder(command).redirectErrorStream(true).start();
        String output = new String(process.getInputStream().readAllBytes(), StandardCharsets.UTF_8);
        int exitCode = process.waitFor();
        assertThat(exitCode).as("keytool %s failed:%n%s", String.join(" ", args), output).isZero();
    }

    private static KeyStore loadKeyStore(Path dir, String fileName) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(dir.resolve(fileName))) {
            keyStore.load(in, STORE_PASSWORD);
        }
        return keyStore;
    }

    private static SSLContext buildServerSslContext(Path dir) throws Exception {
        KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(loadKeyStore(dir, "server.p12"), STORE_PASSWORD);
        TrustManagerFactory trustManagerFactory =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(loadKeyStore(dir, "server-truststore.p12"));
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);
        return sslContext;
    }

    private static SslBundle buildClientSslBundle(Path dir) {
        JksSslStoreDetails keyStoreDetails =
                new JksSslStoreDetails("PKCS12", null, "file:" + p(dir, "client.p12"), "changeit");
        JksSslStoreDetails trustStoreDetails =
                new JksSslStoreDetails("PKCS12", null, "file:" + p(dir, "client-truststore.p12"), "changeit");
        SslStoreBundle storeBundle = new JksSslStoreBundle(keyStoreDetails, trustStoreDetails);
        return SslBundle.of(storeBundle, SslBundleKey.of("changeit"));
    }
}
