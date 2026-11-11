package com.trust.security.core.authorization;

import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.jspecify.annotations.Nullable;
import org.springframework.aop.support.AopUtils;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

public final class RequiresPermissionAuthorizationManager
        implements AuthorizationManager<MethodInvocation> {

    private final RequiresPermissionResolver permissionResolver;
    private final AuthorizationResourceIdResolver resourceIdResolver;
    private final PermissionContextProviderResolver contextProviderResolver;
    private final PermissionChecker permissionChecker;

    public RequiresPermissionAuthorizationManager(
            RequiresPermissionResolver permissionResolver,
            AuthorizationResourceIdResolver resourceIdResolver,
            PermissionContextProviderResolver contextProviderResolver,
            PermissionChecker permissionChecker) {

        this.permissionResolver =
                Objects.requireNonNull(permissionResolver);

        this.resourceIdResolver =
                Objects.requireNonNull(resourceIdResolver);

        this.contextProviderResolver =
                Objects.requireNonNull(contextProviderResolver);

        this.permissionChecker =
                Objects.requireNonNull(permissionChecker);
    }

    @Override
    public AuthorizationResult authorize(
            Supplier<? extends @Nullable Authentication> authentication,
            @Nullable MethodInvocation invocation) {

        if (invocation == null) {
            return new AuthorizationDecision(false);
        }

        Object target = invocation.getThis();
        RequiresPermission permission = permissionResolver.resolve(
                invocation.getMethod(),
                target != null ? AopUtils.getTargetClass(target) : invocation.getMethod().getDeclaringClass()
        );

        if (permission == null) {
            return new AuthorizationDecision(false);
        }

        Authentication currentAuthentication =
                authentication.get();

        if (currentAuthentication == null) {
            return new AuthorizationDecision(false);
        }

        Map<String, String> context = Map.of();

        Optional<ResolvedAuthorizationResource> resolvedResource =
                resourceIdResolver.resolve(invocation);

        if (resolvedResource.isPresent()) {

            ResolvedAuthorizationResource resource =
                    resolvedResource.get();

            PermissionContextProvider contextProvider =
                    contextProviderResolver.resolve(
                            resource.contextProviderType()
                    );

            if (contextProvider == null) {
                throw new IllegalStateException(
                        "No PermissionContextProvider found for "
                                + resource.contextProviderType().getName()
                );
            }

            context = contextProvider.resolve(
                    resource.id()
            );
        }

        boolean allowed = permissionChecker.isAllowed(
                currentAuthentication,
                permission.resource(),
                permission.scope(),
                context
        );

        return new AuthorizationDecision(allowed);
    }
}