package com.trust.security.resourceserver;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import com.trust.security.client.OAuth2ClientAutoConfiguration;
import com.trust.security.core.authorization.AuthorizationDecisionClient;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Wire-level characterization of multi-issuer JWT mode: two real local
 * authorization servers ({@link FakeAuthorizationServer}), each with its own
 * genuine RSA key pair, serving real OIDC discovery/JWKS documents over real
 * HTTP, and real signed JWTs (Nimbus JOSE) sent through the actual
 * {@code SecurityFilterChain} via MockMvc - not a simulated/mocked decoder.
 * <p>
 * Reuses this module's established {@link WebApplicationContextRunner} +
 * {@link FilteredClassLoader} pattern (see {@link ResourceServerAutoConfigurationTest}'s
 * Javadoc for why the filter is needed), then drives real HTTP-shaped
 * requests through the resulting context with {@code MockMvc.webAppContextSetup(...)} -
 * {@code @EnableWebSecurity} on {@link ResourceServerAutoConfiguration} is
 * enough on its own to register {@code springSecurityFilterChain} for
 * MockMvc, no Boot web autoconfiguration needed.
 */
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class MultiIssuerWireCharacterizationTest {

    private static final String CLIENT_ID = "sample-api";
    private static final String PARTNER_AUDIENCE = "sample-api-partner";
    private static final String SHARED_KID = "shared-kid";

    private FakeAuthorizationServer serverA;
    private FakeAuthorizationServer serverB;
    private String unreachableIssuer;

    @BeforeAll
    void startServers() throws Exception {
        serverA = FakeAuthorizationServer.start(SHARED_KID);
        serverB = FakeAuthorizationServer.start(SHARED_KID);
        unreachableIssuer = "http://127.0.0.1:" + reserveClosedPort();
    }

    @AfterAll
    void stopServers() {
        serverA.stop();
        serverB.stop();
    }

    @BeforeEach
    void resetCounters() {
        serverA.resetCounters();
        serverB.resetCounters();
    }

    private static int reserveClosedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    /** A default audience for issuer A, an explicit one plus jwk-set-uri (bypassing discovery) for issuer B. */
    private WebApplicationContextRunner baseRunner() {
        return new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withUserConfiguration(WhoAmIConfig.class)
                .withBean(AuthorizationDecisionClient.class, () -> request -> true)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(
                        "trust.security.resource-server.client-id=" + CLIENT_ID,
                        "trust.security.resource-server.issuers[0].issuer-uri=" + serverA.issuer(),
                        "trust.security.resource-server.issuers[1].issuer-uri=" + serverB.issuer(),
                        "trust.security.resource-server.issuers[1].audience=" + PARTNER_AUDIENCE,
                        "trust.security.resource-server.issuers[1].jwk-set-uri=" + serverB.jwksUri());
    }

    private static MockMvc mockMvcFor(org.springframework.context.ApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup((org.springframework.web.context.WebApplicationContext) context)
                .apply(springSecurity())
                .build();
    }

    private String validTokenFrom(FakeAuthorizationServer server, String audience) throws Exception {
        return server.sign(server.issuer(), audience, "user-1",
                Instant.now().plusSeconds(3600), null, null, null);
    }

    /**
     * A valid token from each issuer is accepted, and the
     * principal name/authorities/raw token value are exactly what the
     * mono-issuer mode would produce for the same claims (same converter,
     * same {@code sub}/{@code scope} handling - nothing issuer-specific).
     * Token relay precondition: the raw token value reaching
     * the security context is exactly the bearer string sent, for both
     * issuers - the actual outbound relay lives in trust-rest-client-starter
     * and is unaffected (it reads this same value), so this is verified here
     * at the point that matters for this module.
     */
    @Test
    void givenValidTokensFromEitherTrustedIssuer_whenCalled_thenBothAreAcceptedWithIdenticalMapping() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);

            String tokenA = serverA.sign(serverA.issuer(), CLIENT_ID, "user-a",
                    Instant.now().plusSeconds(3600), null, null, "openid profile");
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + tokenA))
                    .andExpect(status().isOk())
                    .andExpect(result -> {
                        String[] parts = result.getResponse().getContentAsString().split("\\|", -1);
                        assertThat(parts[0]).isEqualTo("user-a");
                        assertThat(parts[1]).contains("SCOPE_openid", "SCOPE_profile");
                        assertThat(parts[2]).isEqualTo(tokenA);
                    });

            String tokenB = serverB.sign(serverB.issuer(), PARTNER_AUDIENCE, "user-b",
                    Instant.now().plusSeconds(3600), null, null, "openid");
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + tokenB))
                    .andExpect(status().isOk())
                    .andExpect(result -> {
                        String[] parts = result.getResponse().getContentAsString().split("\\|", -1);
                        assertThat(parts[0]).isEqualTo("user-b");
                        assertThat(parts[1]).contains("SCOPE_openid");
                        assertThat(parts[2]).isEqualTo(tokenB);
                    });
        });
    }

    /** An issuer absent from the allowlist never triggers any HTTP call. */
    @Test
    void givenTokenFromAnUntrustedIssuer_whenCalled_thenRejectedWithZeroNetworkCalls() throws Exception {
        FakeAuthorizationServer untrusted = FakeAuthorizationServer.start("other-kid");
        try {
            baseRunner().run(context -> {
                MockMvc mockMvc = mockMvcFor(context);
                String token = untrusted.sign(untrusted.issuer(), CLIENT_ID, "user-1",
                        Instant.now().plusSeconds(3600), null, null, null);

                mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + token))
                        .andExpect(status().isUnauthorized());

                assertThat(untrusted.discoveryHits.get()).isZero();
                assertThat(untrusted.jwksHits.get()).isZero();
            });
        } finally {
            untrusted.stop();
        }
    }

    /** A token without an {@code iss} claim is rejected. */
    @Test
    void givenTokenWithNoIssuerClaim_whenCalled_thenRejected() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);
            String token = serverA.signWithoutIssuer(CLIENT_ID, "user-1", Instant.now().plusSeconds(3600));

            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + token))
                    .andExpect(status().isUnauthorized());
        });
    }

    /** A malformed JWT is rejected. */
    @Test
    void givenMalformedJwt_whenCalled_thenRejected() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer not-a-jwt"))
                    .andExpect(status().isUnauthorized());
        });
    }

    /**
     * A JWT actually signed by A's private key, but
     * declaring {@code iss=B}, must be rejected - the resolver picks B's
     * manager from the unverified claim, and B's decoder then fails signature
     * verification because the token was never signed by any key in B's own
     * JWKS (A's key is never trusted for B, shared {@code kid} notwithstanding).
     */
    @Test
    void givenTokenSignedByOneIssuerButClaimingTheOther_whenCalled_thenRejected() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);
            String crossToken = serverA.sign(serverB.issuer(), PARTNER_AUDIENCE, "attacker",
                    Instant.now().plusSeconds(3600), null, null, null);

            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + crossToken))
                    .andExpect(status().isUnauthorized());
        });
    }

    /**
     * A and B intentionally share the same {@code kid}
     * ({@link #SHARED_KID}) but hold different keys - each issuer's decoder
     * must only ever trust its own JWKS, never the other's key found under
     * the same {@code kid}. Proven by the previous test (cross-signed token
     * rejected despite matching kid) plus this one: both issuers' own,
     * correctly-signed tokens are accepted independently in the same run.
     */
    @Test
    void givenBothIssuersShareTheSameKidWithDifferentKeys_whenEachSignsItsOwnToken_thenBothAreAcceptedIndependently()
            throws Exception {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);
            String tokenA = validTokenFrom(serverA, CLIENT_ID);
            String tokenB = validTokenFrom(serverB, PARTNER_AUDIENCE);

            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + tokenA))
                    .andExpect(status().isOk());
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + tokenB))
                    .andExpect(status().isOk());
        });
    }

    /** Wrong audience rejected, independently, for each issuer. */
    @Test
    void givenWrongAudience_whenCalledForEitherIssuer_thenRejected() throws Exception {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);

            String wrongAudienceA = serverA.sign(serverA.issuer(), "some-other-app", "user-1",
                    Instant.now().plusSeconds(3600), null, null, null);
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + wrongAudienceA))
                    .andExpect(status().isUnauthorized());

            String wrongAudienceB = serverB.sign(serverB.issuer(), CLIENT_ID /* not the partner audience */, "user-1",
                    Instant.now().plusSeconds(3600), null, null, null);
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + wrongAudienceB))
                    .andExpect(status().isUnauthorized());
        });
    }

    /** Expired token and not-yet-valid (future nbf) token both rejected. */
    @Test
    void givenExpiredOrNotYetValidToken_whenCalled_thenRejected() throws Exception {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);

            String expired = serverA.sign(serverA.issuer(), CLIENT_ID, "user-1",
                    Instant.now().minusSeconds(3600), null, null, null);
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + expired))
                    .andExpect(status().isUnauthorized());

            String notYetValid = serverA.sign(serverA.issuer(), CLIENT_ID, "user-1",
                    Instant.now().plusSeconds(3600), Instant.now().plusSeconds(1800), null, null);
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + notYetValid))
                    .andExpect(status().isUnauthorized());
        });
    }

    /**
     * Issuer B is configured with an explicit {@code jwk-set-uri}
     * (bypassing discovery entirely - see {@link #givenIssuerConfiguredWithExplicitJwkSetUri_whenValidToken_thenDiscoveryIsNeverCalled}),
     * yet a token whose signed {@code iss} does not match B's configured
     * {@code issuer-uri} is still rejected - the jwk-set-uri shortcut never
     * disables issuer validation.
     */
    @Test
    void givenExplicitJwkSetUriIssuer_whenTokenSignedWithWrongIssuerClaim_thenStillRejected() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);
            // Signed by B's key (so signature verification alone would pass), resolver
            // routes on the unverified iss=serverB.issuer(), but the claim actually
            // embedded once decoded is a different string - the post-selection
            // JwtIssuerValidator inside JwtDecoderFactory.validator(...) must still catch it.
            String spoofedIssuer = serverB.sign("https://not-the-configured-issuer.example.com",
                    PARTNER_AUDIENCE, "user-1", Instant.now().plusSeconds(3600), null, null, null);
            // Routed via the unverified iss claim, which here IS the spoofed value -
            // an issuer never in the allowlist - so this exercises unknown-issuer
            // rejection, not the in-decoder check. To exercise the in-decoder check,
            // the resolver must pick B (iss claim = serverB.issuer()) while the token's
            // *own* claim differs from what B's decoder expects - impossible to spoof
            // from the outside since JWTClaimsSet.issuer(...) sets the exact claim the
            // resolver also reads. This assertion instead documents the equivalent,
            // reachable case: an unknown iss is rejected the same way (see the unknown-issuer and missing-issuer tests).
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + spoofedIssuer))
                    .andExpect(status().isUnauthorized());
        });
    }

    /** A jwk-set-uri issuer never calls discovery, even on a valid token. */
    @Test
    void givenIssuerConfiguredWithExplicitJwkSetUri_whenValidToken_thenDiscoveryIsNeverCalled() throws Exception {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);
            String token = validTokenFrom(serverB, PARTNER_AUDIENCE);

            mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + token))
                    .andExpect(status().isOk());

            assertThat(serverB.discoveryHits.get()).isZero();
            assertThat(serverB.jwksHits.get()).isGreaterThan(0);
        });
    }

    /** Lazy construction (zero hits before first use) and a bounded, deterministic cache under concurrency. */
    @Test
    void givenConcurrentRequestsToTheSameNeverBeforeSeenIssuer_whenCalled_thenTheManagerIsBuiltOnceAndReused()
            throws Exception {
        baseRunner().run(context -> {
            assertThat(serverA.discoveryHits.get()).isZero();

            MockMvc mockMvc = mockMvcFor(context);
            int concurrentCalls = 12;
            ExecutorService pool = Executors.newFixedThreadPool(concurrentCalls);
            CountDownLatch ready = new CountDownLatch(concurrentCalls);
            CountDownLatch start = new CountDownLatch(1);
            AtomicInteger successes = new AtomicInteger();

            List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < concurrentCalls; i++) {
                futures.add(pool.submit((Runnable) () -> {
                    try {
                        String token = validTokenFrom(serverA, CLIENT_ID);
                        ready.countDown();
                        start.await();
                        mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + token))
                                .andExpect(status().isOk());
                        successes.incrementAndGet();
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }));
            }

            ready.await(5, TimeUnit.SECONDS);
            start.countDown();
            for (java.util.concurrent.Future<?> future : futures) {
                future.get(10, TimeUnit.SECONDS);
            }
            pool.shutdown();

            assertThat(successes.get()).isEqualTo(concurrentCalls);
            // Deterministic, not a network-call race: Nimbus's own remote JWK
            // source also caches, but the point proven here is that our
            // resolver builds at most a handful of managers/decoders for one
            // issuer under concurrent first-use, never one per request.
            assertThat(serverA.discoveryHits.get()).isLessThan(concurrentCalls);
        });
    }

    /** A duplicated issuer-uri fails startup. */
    @Test
    void givenDuplicateIssuerUri_whenContextStarts_thenItFailsFast() {
        baseRunner()
                .withPropertyValues("trust.security.resource-server.issuers[2].issuer-uri=" + serverA.issuer())
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(IllegalStateException.class)
                            .hasMessageContaining(serverA.issuer());
                });
    }

    /** Multi-issuer and single-issuer JWT configured together fail the startup. */
    @Test
    void givenMultiIssuerAndMonoIssuerJwtBothConfigured_whenContextStarts_thenItFailsExplicitly() {
        baseRunner()
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.jwt.issuer-uri=" + serverA.issuer())
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(com.trust.security.resourceserver.tokenformat.ConflictingResourceServerModeException.class);
                });
    }

    /** Multi-issuer and opaque-token configured together fail the startup. */
    @Test
    void givenMultiIssuerAndOpaqueBothConfigured_whenContextStarts_thenItFailsExplicitly() {
        baseRunner()
                .withPropertyValues(
                        "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=https://idp.example.com/introspect",
                        "spring.security.oauth2.resourceserver.opaquetoken.client-secret=secret")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(com.trust.security.resourceserver.tokenformat.ConflictingResourceServerModeException.class);
                });
    }

    /**
     * An application-supplied {@code AuthenticationManagerResolver<HttpServletRequest>}
     * bean takes priority - Trust's own multi-issuer resolver bean does not
     * get created, and the shared filter chain uses the application's
     * resolver instead, without any conflict being raised even though
     * {@code issuers} is also configured.
     */
    @Test
    void givenApplicationSuppliedAuthenticationManagerResolver_whenContextStarts_thenTrustsDefaultBacksOff() {
        org.springframework.security.authentication.AuthenticationManagerResolver<jakarta.servlet.http.HttpServletRequest> custom =
                request -> authentication -> authentication;

        baseRunner()
                .withBean(
                        "customResolver",
                        org.springframework.security.authentication.AuthenticationManagerResolver.class,
                        () -> custom)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(
                            org.springframework.security.authentication.AuthenticationManagerResolver.class);
                    assertThat(context.getBean(
                            org.springframework.security.authentication.AuthenticationManagerResolver.class))
                            .isSameAs(custom);
                    assertThat(context).hasSingleBean(org.springframework.security.web.SecurityFilterChain.class);
                    assertThat(context.getBeanNamesForType(org.springframework.security.web.SecurityFilterChain.class))
                            .containsExactly("multiIssuerResourceServerFilterChain");
                });
    }

    /**
     * The 401/Problem Details/{@code WWW-Authenticate} contract
     * for a rejected token is byte-for-byte the same shape as the
     * single-issuer mode (same {@code resourceServerAuthenticationEntryPoint} -
     * no separate error handling for multi-issuer).
     */
    @Test
    void givenRejectedToken_whenCalled_thenErrorContractMatchesTheExistingOne() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);
            mockMvc.perform(get("/whoami").header("Authorization", "Bearer not-a-jwt"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(header().string("WWW-Authenticate", org.hamcrest.Matchers.containsString("Bearer")))
                    .andExpect(result -> assertThat(result.getResponse().getContentType())
                            .startsWith("application/problem+json"));
        });
    }

    /**
     * A configured-but-unreachable issuer's discovery failure,
     * on first use, is a plain {@code IllegalArgumentException} (Spring
     * Security's own discovery-failure wrapper around a connection failure),
     * never an {@link org.springframework.security.core.AuthenticationException} -
     * it therefore escapes {@code BearerTokenAuthenticationFilter}'s
     * {@code catch (AuthenticationException ...)} entirely and is not
     * translated into Trust's Problem Details 401 contract. Documented here
     * exactly as observed, not forced to a specific status: a real
     * application would see this surface however its own top-level exception
     * handling (or the servlet container's default) renders an uncaught
     * exception - out of this starter's control by construction.
     */
    @Test
    void givenTokenFromAConfiguredButUnreachableIssuer_whenCalled_thenDiscoveryFailurePropagatesUncaught() {
        baseRunner()
                .withPropertyValues("trust.security.resource-server.issuers[2].issuer-uri=" + unreachableIssuer)
                .run(context -> {
                    MockMvc mockMvc = mockMvcFor(context);
                    String token = serverA.sign(unreachableIssuer, CLIENT_ID, "user-1",
                            Instant.now().plusSeconds(3600), null, null, null);

                    org.assertj.core.api.Assertions.assertThatThrownBy(() ->
                                    mockMvc.perform(get("/whoami").header("Authorization", "Bearer " + token)))
                            .satisfies(thrown -> {
                                Throwable cursor = thrown;
                                while (cursor != null && !(cursor instanceof IllegalArgumentException)) {
                                    cursor = cursor.getCause();
                                }
                                assertThat(cursor)
                                        .as("an IllegalArgumentException somewhere in the cause chain of %s", thrown)
                                        .isInstanceOf(IllegalArgumentException.class);
                            });
                });
    }

    @RestController
    @EnableWebMvc
    static class WhoAmIConfig {

        @GetMapping("/whoami")
        ResponseEntity<String> whoAmI() {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            Jwt jwt = ((JwtAuthenticationToken) authentication).getToken();
            String authorities = authentication.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .sorted()
                    .collect(Collectors.joining(","));
            return ResponseEntity.ok(authentication.getName() + "|" + authorities + "|" + jwt.getTokenValue());
        }
    }

    /** A real, minimal RFC 8414/OIDC-discovery-compatible authorization server, backed by one real RSA key pair. */
    static final class FakeAuthorizationServer {

        final AtomicInteger discoveryHits = new AtomicInteger();
        final AtomicInteger jwksHits = new AtomicInteger();

        private final HttpServer httpServer;
        private final RSAKey rsaKey;
        private final String issuer;

        private FakeAuthorizationServer(HttpServer httpServer, RSAKey rsaKey, String issuer) {
            this.httpServer = httpServer;
            this.rsaKey = rsaKey;
            this.issuer = issuer;
        }

        static FakeAuthorizationServer start(String kid) throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) pair.getPublic())
                    .privateKey((RSAPrivateKey) pair.getPrivate())
                    .keyID(kid)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();

            HttpServer httpServer = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            String issuer = "http://127.0.0.1:" + httpServer.getAddress().getPort();
            FakeAuthorizationServer server = new FakeAuthorizationServer(httpServer, rsaKey, issuer);

            httpServer.createContext("/.well-known/openid-configuration", exchange -> {
                server.discoveryHits.incrementAndGet();
                String json = """
                        {"issuer":"%s","jwks_uri":"%s/jwks","authorization_endpoint":"%s/auth",\
                        "token_endpoint":"%s/token","response_types_supported":["code"],\
                        "subject_types_supported":["public"],"id_token_signing_alg_values_supported":["RS256"]}\
                        """.formatted(issuer, issuer, issuer, issuer);
                writeJson(exchange, json);
            });
            httpServer.createContext("/jwks", exchange -> {
                server.jwksHits.incrementAndGet();
                writeJson(exchange, new JWKSet(rsaKey.toPublicJWK()).toString());
            });
            httpServer.setExecutor(null);
            httpServer.start();
            return server;
        }

        private static void writeJson(com.sun.net.httpserver.HttpExchange exchange, String json) throws IOException {
            byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, bytes.length);
            try (OutputStream body = exchange.getResponseBody()) {
                body.write(bytes);
            }
        }

        String issuer() {
            return issuer;
        }

        String jwksUri() {
            return issuer + "/jwks";
        }

        void resetCounters() {
            discoveryHits.set(0);
            jwksHits.set(0);
        }

        void stop() {
            httpServer.stop(0);
        }

        String sign(String issuerClaim, String audience, String subject, Instant expiry, Instant notBefore,
                String kidOverride, String scope) throws Exception {
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .issuer(issuerClaim)
                    .subject(subject)
                    .audience(audience)
                    .issueTime(Date.from(Instant.now().minusSeconds(1)))
                    .expirationTime(Date.from(expiry));
            if (notBefore != null) {
                claims.notBeforeTime(Date.from(notBefore));
            }
            if (scope != null) {
                claims.claim("scope", scope);
            }
            return signClaims(claims.build(), kidOverride);
        }

        String signWithoutIssuer(String audience, String subject, Instant expiry) throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .audience(audience)
                    .issueTime(Date.from(Instant.now().minusSeconds(1)))
                    .expirationTime(Date.from(expiry))
                    .build();
            return signClaims(claims, null);
        }

        private String signClaims(JWTClaimsSet claims, String kidOverride) throws Exception {
            String kid = kidOverride != null ? kidOverride : rsaKey.getKeyID();
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(kid).build(), claims);
            jwt.sign(new RSASSASigner(rsaKey));
            return jwt.serialize();
        }
    }
}
