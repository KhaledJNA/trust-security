package com.trust.security.core.authorization;

import java.util.Objects;

import org.springframework.context.ApplicationContext;

public final class SpringPermissionContextProviderResolver
        implements PermissionContextProviderResolver {

    private final ApplicationContext applicationContext;

    public SpringPermissionContextProviderResolver(
            ApplicationContext applicationContext) {

        this.applicationContext =
                Objects.requireNonNull(
                        applicationContext,
                        "applicationContext must not be null"
                );
    }

    @Override
    public PermissionContextProvider resolve(
            Class<? extends PermissionContextProvider> providerType) {

        return applicationContext.getBean(providerType);
    }
}