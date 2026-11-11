package com.trust.security.core.authorization;

import java.lang.reflect.Method;
import java.util.Objects;

import org.springframework.aop.support.StaticMethodMatcherPointcut;

public final class RequiresPermissionPointcut
        extends StaticMethodMatcherPointcut {

    private final RequiresPermissionResolver resolver;

    public RequiresPermissionPointcut(
            RequiresPermissionResolver resolver) {
        this.resolver = Objects.requireNonNull(
                resolver,
                "resolver must not be null"
        );
    }

    @Override
    public boolean matches(Method method, Class<?> targetClass) {
        return resolver.resolve(method, targetClass) != null;
    }
}