package com.trust.security.resourceserver.jwt;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.*;

import java.util.List;

/**
 * Builds the JWT decoder used by resource servers.
 *
 * <p>Audience validation is derived from {@code trust.security.resource-server.client-id}
 * rather than declared separately: an application's OAuth2 client identifier
 * is also the audience it expects in incoming tokens. Without this check, the
 * API would accept any token issued by the realm, including those intended for
 * other applications.
 */
public final class JwtDecoderFactory {

    private static final String AUDIENCE_CLAIM = "aud";

    private JwtDecoderFactory() {
    }

    /**
     * The issuer's discovery document is fetched on the first token, not at
     * startup (as Spring Boot's own decoder does): the application starts,
     * and its tests run, while the issuer is unreachable. A failed discovery
     * is retried on the next token.
     */
    public static JwtDecoder create(String issuerUri, String expectedAudience) {
        return new SupplierJwtDecoder(() -> {
            NimbusJwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuerUri);
            decoder.setJwtValidator(validator(issuerUri, expectedAudience));
            return decoder;
        });
    }

    /**
     * Shared by {@link #create(String, String)} (discovery-based) and the
     * multi-issuer resolver's {@code jwk-set-uri} path (bypasses discovery
     * for the key source, but must never bypass this validator - issuer,
     * audience, expiry, not-before and clock skew stay identical either way).
     */
    static OAuth2TokenValidator<Jwt> validator(String issuerUri, String expectedAudience) {
        return new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuerUri),
                audienceValidator(expectedAudience));
    }

    private static OAuth2TokenValidator<Jwt> audienceValidator(String expectedAudience) {
        return new JwtClaimValidator<List<String>>(
                AUDIENCE_CLAIM,
                audiences -> {
                    return audiences != null && audiences.contains(expectedAudience);
                });
    }
}