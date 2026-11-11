package com.trust.security.core.user;

import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Optional;

/**
 * Reads the current user from the security context, for JWT, OIDC login and
 * opaque-token principals alike (see {@link PrincipalClaims}).
 */
public final class SecurityContextCurrentUserProvider
        implements CurrentUserProvider {

    @Override
    public Optional<AuthenticatedUser> getCurrentUser() {
        return PrincipalClaims.of(SecurityContextHolder.getContext().getAuthentication())
                .flatMap(SecurityContextCurrentUserProvider::toUser);
    }

    private static Optional<AuthenticatedUser> toUser(PrincipalClaims claims) {
        String subject = claims.getAsString("sub");
        if (subject == null) {
            return Optional.empty();
        }
        return Optional.of(new AuthenticatedUser(
                subject,
                claims.getAsString("preferred_username"),
                claims.getAsString("email")));
    }
}
