package com.trust.security.resourceserver.tokenformat;

/**
 * Thrown at startup when both a {@link org.springframework.security.oauth2.jwt.JwtDecoder}
 * and an {@link org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector}
 * bean are available at once.
 * <p>
 * Without this guard, both {@code jwtResourceServerFilterChain} and
 * {@code opaqueTokenResourceServerFilterChain} in {@code ResourceServerAutoConfiguration}
 * would be individually eligible, and only Spring's bean-registration order
 * would decide, silently, which one actually wins - precisely the kind of
 * implicit, bean-presence-driven selection Trust also refuses for outbound
 * token relay. Resource-server token format must be
 * unambiguous by construction, never a coin flip of declaration order.
 */
public final class AmbiguousTokenFormatException extends RuntimeException {

    static final String DESCRIPTION =
            "Both a JWT decoder (spring.security.oauth2.resourceserver.jwt.issuer-uri, or an "
            + "application-supplied JwtDecoder bean) and an opaque token introspector "
            + "(spring.security.oauth2.resourceserver.opaquetoken.introspection-uri, or an "
            + "application-supplied OpaqueTokenIntrospector bean) are present at once. "
            + "trust-security-resource-server-starter validates a token exactly one way per "
            + "application, never both.";

    static final String ACTION =
            "Keep only one token format for this resource server: remove the JWT properties/bean "
            + "for an opaque-only resource server, or the opaque-token properties/bean for a "
            + "JWT-only one. If both formats are genuinely needed, they belong to two separate "
            + "resource server applications, not one.";

    public AmbiguousTokenFormatException() {
        super(DESCRIPTION);
    }
}
