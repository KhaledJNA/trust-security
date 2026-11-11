package com.trust.security.core.acr;

import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.springframework.aop.support.AopUtils;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

import java.util.Objects;
import java.util.function.Supplier;

public final class RequiresAcrAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    private final AcrAuthorization acrAuthorization;

    public RequiresAcrAuthorizationManager(AcrAuthorization acrAuthorization) {
        this.acrAuthorization = Objects.requireNonNull(
                acrAuthorization, "acrAuthorization must not be null");
    }

    @Override
    public AuthorizationResult authorize(
            Supplier<? extends @Nullable Authentication> authentication,
            MethodInvocation invocation) {

        RequiresAcr requiresAcr = RequiresAcrResolver.resolve(invocation.getMethod(), targetClass(invocation));

        if (requiresAcr == null) {
            return new AcrAuthorizationResult(true, null);
        }

        boolean granted = acrAuthorization.hasAcr(authentication.get(), requiresAcr.value());
        return new AcrAuthorizationResult(granted, requiresAcr.value());
    }

    static Class<?> targetClass(MethodInvocation invocation) {
        Object target = invocation.getThis();
        return target != null ? AopUtils.getTargetClass(target) : invocation.getMethod().getDeclaringClass();
    }
}
