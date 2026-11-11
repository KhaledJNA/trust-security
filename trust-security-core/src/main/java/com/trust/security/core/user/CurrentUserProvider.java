package com.trust.security.core.user;

import java.util.Optional;

public interface CurrentUserProvider {

    /**
     * @return the current caller, or empty when there is none: no or anonymous
     *         authentication, a principal without claims, or no {@code sub} claim
     */
    Optional<AuthenticatedUser> getCurrentUser();
}
