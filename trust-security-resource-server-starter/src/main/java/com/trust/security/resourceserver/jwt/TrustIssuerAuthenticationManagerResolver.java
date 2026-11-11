package com.trust.security.resourceserver.jwt;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.util.StringUtils;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Resolves the {@link AuthenticationManager} to use for a JWT based purely on
 * its unverified {@code iss} claim, looked up by exact string equality in a
 * closed, static allowlist built from {@code trust.security.resource-server.issuers}.
 * Wrapped by {@link org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver}
 * (Spring Security's own request-level dispatcher), which is what actually
 * extracts that claim from the bearer token.
 * <p>
 * Deliberately does not use {@code JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(...)}:
 * that factory builds, per issuer, a plain {@link JwtDecoder} and Spring
 * Security's own default {@link JwtAuthenticationConverter} internally, with
 * no extension point to install Trust's authorities mapping - it would
 * silently diverge from the single-issuer mode's authorities/principal
 * mapping. This class instead builds each issuer's {@link AuthenticationManager}
 * itself, reusing the exact same {@link JwtDecoderFactory} validators and the
 * one {@link JwtAuthenticationConverter} instance (carrying Trust's composite
 * authorities converter) the caller passes in - identical to the single-issuer
 * mode for every issuer.
 * <p>
 * An issuer absent from the allowlist, blank, or missing entirely never
 * triggers a network call and never falls back to any default issuer -
 * rejected immediately as {@link InvalidBearerTokenException}, the same
 * exception type (and therefore the same 401/{@code WWW-Authenticate}
 * contract) an actually-invalid JWT would produce.
 */
public final class TrustIssuerAuthenticationManagerResolver implements AuthenticationManagerResolver<String> {

    private final Map<String, IssuerProperties> issuersByUri;
    private final String defaultAudience;
    private final JwtAuthenticationConverter jwtAuthenticationConverter;
    private final ConcurrentHashMap<String, AuthenticationManager> cache = new ConcurrentHashMap<>();

    public TrustIssuerAuthenticationManagerResolver(
            List<IssuerProperties> issuers,
            String defaultAudience,
            JwtAuthenticationConverter jwtAuthenticationConverter) {

        this.issuersByUri = indexByIssuerUri(issuers);
        this.defaultAudience = defaultAudience;
        this.jwtAuthenticationConverter = Objects.requireNonNull(
                jwtAuthenticationConverter, "jwtAuthenticationConverter must not be null");
    }

    private static Map<String, IssuerProperties> indexByIssuerUri(List<IssuerProperties> issuers) {
        Map<String, IssuerProperties> byUri = new LinkedHashMap<>();
        for (IssuerProperties issuer : issuers) {
            IssuerProperties previous = byUri.putIfAbsent(issuer.getIssuerUri(), issuer);
            if (previous != null) {
                throw new IllegalStateException(
                        ("trust.security.resource-server.issuers declares issuer-uri '%s' more than once - "
                                + "each trusted issuer must appear exactly once.")
                                .formatted(issuer.getIssuerUri()));
            }
        }
        return Map.copyOf(byUri);
    }

    @Override
    public AuthenticationManager resolve(String issuer) {
        if (!StringUtils.hasText(issuer)) {
            throw new InvalidBearerTokenException("Missing or blank iss claim");
        }
        IssuerProperties config = issuersByUri.get(issuer);
        if (config == null) {
            throw new InvalidBearerTokenException("Unknown issuer: '%s'".formatted(issuer));
        }
        return cache.computeIfAbsent(issuer, ignored -> buildManager(config));
    }

    private AuthenticationManager buildManager(IssuerProperties config) {
        String audience = StringUtils.hasText(config.getAudience()) ? config.getAudience() : defaultAudience;
        JwtDecoder decoder = StringUtils.hasText(config.getJwkSetUri())
                ? decoderFromJwkSetUri(config.getIssuerUri(), config.getJwkSetUri(), audience)
                : JwtDecoderFactory.create(config.getIssuerUri(), audience);

        JwtAuthenticationProvider provider = new JwtAuthenticationProvider(decoder);
        provider.setJwtAuthenticationConverter(jwtAuthenticationConverter);
        return new ProviderManager(provider);
    }

    private static JwtDecoder decoderFromJwkSetUri(String issuerUri, String jwkSetUri, String audience) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(JwtDecoderFactory.validator(issuerUri, audience));
        return decoder;
    }
}
