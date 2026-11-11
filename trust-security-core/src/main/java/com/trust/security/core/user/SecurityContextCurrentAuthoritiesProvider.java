package com.trust.security.core.user;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public final class SecurityContextCurrentAuthoritiesProvider
        implements CurrentAuthoritiesProvider {

    /**
     * An anonymous caller has no authorities here, even though Spring gives
     * {@code AnonymousAuthenticationToken} a {@code ROLE_ANONYMOUS} authority.
     */
    @Override
    public Set<String> getAuthorities() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !PrincipalClaims.isAuthenticated(authentication)) {
            return Set.of();
        }

        return authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull)
                .collect(Collectors.toUnmodifiableSet());
    }
}
