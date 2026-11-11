package com.trust.security.client.tenant;

import jakarta.servlet.http.HttpServletRequest;

import java.util.Optional;

/**
 * Resolves a Spring {@code registrationId} from a login-initiation request
 * that does not itself name one - typically a tenant-specific host or path,
 * matched against a closed, statically configured allowlist.
 * <p>
 * No abstraction equivalent to this exists in Spring itself: Spring Security
 * resolves a {@code registrationId} either from the {@code /oauth2/authorization/{registrationId}}
 * path variable, or from an explicitly passed id - never from an
 * application-defined mapping table. This interface fills exactly that one
 * gap, nothing more; the actual OAuth2 authorization request construction,
 * redirect, callback handling, and token exchange stay entirely Spring's own,
 * invoked only once a {@code registrationId} has been determined - see
 * {@link TenantLoginRequestFilter}.
 * <p>
 * An application may supply its own bean of this type ({@code @ConditionalOnMissingBean})
 * to resolve tenants a different way (e.g. from a database) - it fully
 * replaces Trust's host/path-based default, never composed with it.
 */
public interface TrustRegistrationIdResolver {

    /**
     * @param request the incoming request, already confirmed by the caller to
     *                match the configured {@code request-pattern}
     * @return the resolved {@code registrationId}, or {@link Optional#empty()}
     *         when the request carries no value this resolver recognizes -
     *         never throws for that case, and never invents a default
     */
    Optional<String> resolve(HttpServletRequest request);
}
