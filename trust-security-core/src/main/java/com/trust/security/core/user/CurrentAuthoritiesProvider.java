package com.trust.security.core.user;

import java.util.Set;

public interface CurrentAuthoritiesProvider {

    /** @return the current caller's authorities; empty when unauthenticated or anonymous */
    Set<String> getAuthorities();
}
