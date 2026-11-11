package com.trust.security.resourceserver.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Fast, network-free tests for {@link TrustIssuerAuthenticationManagerResolver}:
 * everything that can be verified without actually building a {@link org.springframework.security.oauth2.jwt.JwtDecoder}
 * (which always requires either OIDC discovery or a JWKS fetch - covered
 * instead, with two real local authorization servers, by
 * {@link MultiIssuerWireCharacterizationTest}).
 */
class TrustIssuerAuthenticationManagerResolverTest {

    private static final String ISSUER_A = "https://idp-a.example.com/realms/trust";
    private static final String ISSUER_B = "https://idp-b.example.com/realms/partner";

    private static IssuerProperties issuer(String issuerUri) {
        IssuerProperties properties = new IssuerProperties();
        properties.setIssuerUri(issuerUri);
        return properties;
    }

    @Test
    void givenTwoEntriesDeclareTheSameIssuerUri_whenConstructing_thenItFailsFastNamingTheDuplicate() {
        assertThatThrownBy(() -> new TrustIssuerAuthenticationManagerResolver(
                List.of(issuer(ISSUER_A), issuer(ISSUER_A)),
                "sample-api",
                new JwtAuthenticationConverter()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining(ISSUER_A);
    }

    @Test
    void givenNullIssuer_whenResolving_thenItRejectsWithoutAnyNetworkCall() {
        TrustIssuerAuthenticationManagerResolver resolver = new TrustIssuerAuthenticationManagerResolver(
                List.of(issuer(ISSUER_A)), "sample-api", new JwtAuthenticationConverter());

        long start = System.nanoTime();
        assertThatThrownBy(() -> resolver.resolve(null))
                .isInstanceOf(InvalidBearerTokenException.class);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        assertThat(elapsedMs).isLessThan(500);
    }

    @Test
    void givenBlankIssuer_whenResolving_thenItRejectsWithoutAnyNetworkCall() {
        TrustIssuerAuthenticationManagerResolver resolver = new TrustIssuerAuthenticationManagerResolver(
                List.of(issuer(ISSUER_A)), "sample-api", new JwtAuthenticationConverter());

        assertThatThrownBy(() -> resolver.resolve("   "))
                .isInstanceOf(InvalidBearerTokenException.class);
    }

    /**
     * The critical zero-network-call assertion: {@code ISSUER_B} is a real,
     * resolvable-looking HTTPS host that this resolver is never configured to
     * trust. If resolving it attempted OIDC discovery, the call would block
     * on DNS/TCP for seconds (real timeout is 30s) rather than fail
     * near-instantly - the elapsed-time bound is what proves no attempt was
     * made, not just the exception type.
     */
    @Test
    void givenUnknownIssuer_whenResolving_thenItRejectsNamingTheIssuerWithoutAnyNetworkCall() {
        TrustIssuerAuthenticationManagerResolver resolver = new TrustIssuerAuthenticationManagerResolver(
                List.of(issuer(ISSUER_A)), "sample-api", new JwtAuthenticationConverter());

        long start = System.nanoTime();
        assertThatThrownBy(() -> resolver.resolve(ISSUER_B))
                .isInstanceOf(InvalidBearerTokenException.class)
                .hasMessageContaining(ISSUER_B);
        long elapsedMs = (System.nanoTime() - start) / 1_000_000;

        assertThat(elapsedMs).isLessThan(500);
    }

    @Test
    void givenIssuerUriWithTrailingSlashDifference_whenResolving_thenItIsTreatedAsAnUnknownIssuer() {
        TrustIssuerAuthenticationManagerResolver resolver = new TrustIssuerAuthenticationManagerResolver(
                List.of(issuer(ISSUER_A)), "sample-api", new JwtAuthenticationConverter());

        assertThatThrownBy(() -> resolver.resolve(ISSUER_A + "/"))
                .isInstanceOf(InvalidBearerTokenException.class);
    }
}
