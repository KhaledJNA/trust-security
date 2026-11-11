package com.trust.security.core.user;

import org.jspecify.annotations.Nullable;

import java.util.Objects;

/**
 * The current caller, as read from its token claims.
 *
 * @param subject  the {@code sub} claim - always present
 * @param username the {@code preferred_username} claim, if the token carries it
 * @param email    the {@code email} claim, if the token carries it
 */
public record AuthenticatedUser(
        String subject,
        @Nullable String username,
        @Nullable String email
) {

    public AuthenticatedUser {
        Objects.requireNonNull(subject, "subject must not be null");
    }
}
