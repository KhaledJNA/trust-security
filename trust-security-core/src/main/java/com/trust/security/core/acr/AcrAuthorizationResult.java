package com.trust.security.core.acr;

import org.jspecify.annotations.Nullable;
import org.springframework.security.authorization.AuthorizationResult;

/**
 * Outcome of a {@code @RequiresAcr} check, carrying the required ACR so an
 * access-denied handler can ask for step-up (RFC 9470).
 *
 * @param requiredAcr the ACR the method requires; {@code null} only when the
 *                    method carries no {@code @RequiresAcr} at all
 */
public record AcrAuthorizationResult(
        boolean granted,
        @Nullable String requiredAcr
) implements AuthorizationResult {

    @Override
    public boolean isGranted() {
        return granted;
    }
}
