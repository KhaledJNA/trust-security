package com.trust.security.resourceserver.tokenformat;

/**
 * Thrown at startup when {@code trust.security.resource-server.issuers}
 * (multi-issuer JWT mode) is configured at the same time as the single-issuer
 * JWT or opaque-token mode - by property, or by an application-supplied
 * {@link org.springframework.security.oauth2.jwt.JwtDecoder}/{@link org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector}
 * bean.
 * <p>
 * Without this guard, both the multi-issuer filter chain and the
 * single-issuer/opaque one in {@code ResourceServerAutoConfiguration} would
 * individually be eligible, and bean-registration order alone would decide,
 * silently, which one wins - the same class of problem {@link MissingTokenFormatException}/
 * {@link AmbiguousTokenFormatException} already guard against for the
 * two-mode case.
 * <p>
 * An application-supplied {@code AuthenticationManagerResolver<HttpServletRequest>}
 * bean is never a trigger for this exception: that is the documented
 * back-off path, not a conflict - see {@code ResourceServerAutoConfiguration.tokenFormatGuard}.
 */
public final class ConflictingResourceServerModeException extends RuntimeException {

    static final String ACTION =
            "Keep only one resource-server mode: remove trust.security.resource-server.issuers for a "
            + "single-issuer JWT or opaque-token resource server, or remove the single-issuer/opaque-token "
            + "properties (and any JwtDecoder/OpaqueTokenIntrospector bean) for a multi-issuer one.";

    public ConflictingResourceServerModeException(boolean conflictsWithJwt, boolean conflictsWithOpaque) {
        super(buildDescription(conflictsWithJwt, conflictsWithOpaque));
    }

    private static String buildDescription(boolean conflictsWithJwt, boolean conflictsWithOpaque) {
        String other;
        if (conflictsWithJwt && conflictsWithOpaque) {
            other = "both a JWT decoder (spring.security.oauth2.resourceserver.jwt.issuer-uri, or an "
                    + "application-supplied JwtDecoder bean) and an opaque token introspector "
                    + "(spring.security.oauth2.resourceserver.opaquetoken.introspection-uri, or an "
                    + "application-supplied OpaqueTokenIntrospector bean)";
        } else if (conflictsWithJwt) {
            other = "a JWT decoder (spring.security.oauth2.resourceserver.jwt.issuer-uri, or an "
                    + "application-supplied JwtDecoder bean)";
        } else {
            other = "an opaque token introspector "
                    + "(spring.security.oauth2.resourceserver.opaquetoken.introspection-uri, or an "
                    + "application-supplied OpaqueTokenIntrospector bean)";
        }
        return ("trust.security.resource-server.issuers is configured (multi-issuer JWT mode) at the same "
                + "time as %s. trust-security-resource-server-starter validates a token exactly one way per "
                + "application, never more than one at once.").formatted(other);
    }
}
