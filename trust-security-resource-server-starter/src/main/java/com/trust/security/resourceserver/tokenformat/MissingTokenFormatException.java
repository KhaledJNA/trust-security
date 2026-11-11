package com.trust.security.resourceserver.tokenformat;

/**
 * Thrown at startup when neither a {@link org.springframework.security.oauth2.jwt.JwtDecoder}
 * nor an {@link org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector}
 * bean is available - from Trust's own conditional factory methods
 * ({@code spring.security.oauth2.resourceserver.jwt.issuer-uri} /
 * {@code ...opaquetoken.introspection-uri}) or supplied directly by the
 * application.
 * <p>
 * Without this guard, an application in this state would silently fall back
 * to Spring Boot's own default {@code SecurityFilterChain} (HTTP Basic/form
 * login) instead of Trust's Bearer resource server chain - a silent
 * security degradation the Trust libraries never allow.
 */
public final class MissingTokenFormatException extends RuntimeException {

    static final String DESCRIPTION =
            "Neither spring.security.oauth2.resourceserver.jwt.issuer-uri nor "
            + "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri is configured, "
            + "and no application-supplied JwtDecoder or OpaqueTokenIntrospector bean was found. "
            + "trust-security-resource-server-starter cannot install a Bearer token validation "
            + "chain without one of these.";

    static final String ACTION =
            "Set spring.security.oauth2.resourceserver.jwt.issuer-uri for a JWT/JWKS resource "
            + "server, or spring.security.oauth2.resourceserver.opaquetoken.introspection-uri "
            + "(plus client-id/client-secret) for RFC 7662 opaque-token introspection - or supply "
            + "your own JwtDecoder/OpaqueTokenIntrospector bean.";

    public MissingTokenFormatException() {
        super(DESCRIPTION);
    }
}
