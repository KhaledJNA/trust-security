package com.trust.security.core.acr;

import com.trust.security.core.user.PrincipalClaims;
import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;

import java.util.Objects;

/**
 * Checks the {@code acr} claim of the current caller, for JWT, OIDC login and
 * opaque-token principals alike (see {@link PrincipalClaims}).
 */
public class AcrAuthorization {

    private static final String ACR_CLAIM = "acr";

    /**
     * @param authentication the caller; {@code null}, unauthenticated or
     *                       anonymous never has the expected ACR
     * @param expectedAcr    the ACR value the caller requires; never {@code null}
     *                       - a missing expected ACR is a programming/configuration
     *                       error (e.g. {@code @RequiresAcr} misconfigured), not a
     *                       runtime authorization outcome, so it fails fast rather
     *                       than silently denying or matching anything
     */
    public boolean hasAcr(@Nullable Authentication authentication, String expectedAcr) {
        Objects.requireNonNull(expectedAcr, "expectedAcr must not be null");

        return PrincipalClaims.of(authentication)
                .map(claims -> expectedAcr.equals(claims.getAsString(ACR_CLAIM)))
                .orElse(false);
    }
}
