package com.trust.security.core.user;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;

import java.util.Map;
import java.util.Optional;

/**
 * Claims of the current authenticated principal, whatever the token format:
 * <ul>
 *   <li>{@link ClaimAccessor}: JWT ({@code Jwt}) and OIDC login ({@code OidcUser});</li>
 *   <li>{@link OAuth2AuthenticatedPrincipal}: opaque token introspection
 *   (RFC 7662), whose principal exposes attributes, not claims.</li>
 * </ul>
 * Anonymous and unauthenticated authentications have no claims.
 */
public final class PrincipalClaims {

    private static final AuthenticationTrustResolver TRUST_RESOLVER = new AuthenticationTrustResolverImpl();

    private final Map<String, Object> claims;

    private PrincipalClaims(Map<String, Object> claims) {
        this.claims = claims;
    }

    public static Optional<PrincipalClaims> of(@Nullable Authentication authentication) {
        if (authentication == null || !isAuthenticated(authentication)) {
            return Optional.empty();
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof ClaimAccessor accessor) {
            return Optional.of(new PrincipalClaims(accessor.getClaims()));
        }
        if (principal instanceof OAuth2AuthenticatedPrincipal oauth2Principal) {
            return Optional.of(new PrincipalClaims(oauth2Principal.getAttributes()));
        }
        return Optional.empty();
    }

    /**
     * {@code true} for a real, authenticated caller - {@code false} for
     * {@code null}, an unauthenticated token, or an anonymous one (Spring
     * marks {@code AnonymousAuthenticationToken} as authenticated).
     */
    public static boolean isAuthenticated(@Nullable Authentication authentication) {
        return TRUST_RESOLVER.isAuthenticated(authentication);
    }

    /** The claim as a string ({@code toString()} of a non-string value), or {@code null} if absent. */
    public @Nullable String getAsString(String name) {
        Object value = claims.get(name);
        return value == null ? null : value.toString();
    }
}
