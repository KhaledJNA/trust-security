package com.trust.security.resourceserver.jwt;

import jakarta.validation.constraints.NotBlank;

/**
 * One entry of {@code trust.security.resource-server.issuers} - a single
 * trusted issuer in the multi-issuer JWT allowlist.
 *
 * <p>The allowlist is closed and static: no wildcard, suffix matching, or
 * regex is supported, and issuers are never added or removed at runtime.
 * Matching against an incoming token's {@code iss} claim is always exact
 * string equality - a trailing slash difference is a different issuer, never
 * normalized away.
 */
public class IssuerProperties {

    @NotBlank(message = "issuer-uri is required for every entry of "
            + "trust.security.resource-server.issuers")
    private String issuerUri;

    /**
     * Expected {@code aud} claim for tokens from this issuer. Optional: when
     * absent, falls back to {@code trust.security.resource-server.client-id}
     * - the same default the single-issuer mode already uses. Set this only
     * when this specific issuer genuinely issues tokens for a different
     * audience than the resource server's own client id.
     */
    private String audience;

    /**
     * Optional JWKS endpoint, bypassing OIDC discovery for the key source
     * only. Never disables {@code iss} validation: a decoder built from an
     * explicit {@code jwk-set-uri} still requires the signed {@code iss}
     * claim to match this entry's {@code issuer-uri} exactly.
     */
    private String jwkSetUri;

    public String getIssuerUri() {
        return issuerUri;
    }

    public void setIssuerUri(String issuerUri) {
        this.issuerUri = issuerUri;
    }

    public String getAudience() {
        return audience;
    }

    public void setAudience(String audience) {
        this.audience = audience;
    }

    public String getJwkSetUri() {
        return jwkSetUri;
    }

    public void setJwkSetUri(String jwkSetUri) {
        this.jwkSetUri = jwkSetUri;
    }
}
