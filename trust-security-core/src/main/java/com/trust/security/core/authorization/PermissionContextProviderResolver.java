package com.trust.security.core.authorization;

public interface PermissionContextProviderResolver {

    PermissionContextProvider resolve(
            Class<? extends PermissionContextProvider> providerType
    );
}