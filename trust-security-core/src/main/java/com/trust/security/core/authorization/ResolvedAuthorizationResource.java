package com.trust.security.core.authorization;

import java.util.Objects;

public record ResolvedAuthorizationResource(
        Object id,
        Class<? extends PermissionContextProvider> contextProviderType) {

    public ResolvedAuthorizationResource {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(
                contextProviderType,
                "contextProviderType must not be null"
        );
    }
}