package com.trust.security.core.authorization;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.MethodClassKey;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedMethod;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finds the argument annotated with {@link AuthorizationResourceId} on a
 * secured method call.
 * <p>
 * The annotation is found whether it sits on the interface method's
 * parameter or on the implementation's ({@link AnnotatedMethod} merges
 * both). Which parameter carries it is computed once per method and cached.
 */
public final class AuthorizationResourceIdResolver {

    private record IdParameter(int index, Class<? extends PermissionContextProvider> providerType) {
    }

    private final Map<MethodClassKey, Optional<IdParameter>> cache = new ConcurrentHashMap<>();

    /**
     * @throws IllegalStateException if more than one parameter is annotated,
     *                               or the annotated argument is {@code null}
     */
    public Optional<ResolvedAuthorizationResource> resolve(MethodInvocation invocation) {
        Method method = invocation.getMethod();
        Object target = invocation.getThis();
        Class<?> targetClass = target != null ? AopUtils.getTargetClass(target) : method.getDeclaringClass();

        Optional<IdParameter> idParameter = cache.computeIfAbsent(
                new MethodClassKey(method, targetClass), key -> findIdParameter(method, targetClass));

        return idParameter.map(parameter -> {
            Object resourceId = invocation.getArguments()[parameter.index()];
            if (resourceId == null) {
                throw new IllegalStateException("@AuthorizationResourceId value must not be null");
            }
            return new ResolvedAuthorizationResource(resourceId, parameter.providerType());
        });
    }

    private static Optional<IdParameter> findIdParameter(Method method, Class<?> targetClass) {
        Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);
        MethodParameter[] parameters = new AnnotatedMethod(specificMethod).getMethodParameters();

        IdParameter found = null;
        for (MethodParameter parameter : parameters) {
            AuthorizationResourceId annotation = parameter.getParameterAnnotation(AuthorizationResourceId.class);
            if (annotation == null) {
                continue;
            }
            if (found != null) {
                throw new IllegalStateException("Only one @AuthorizationResourceId is allowed per method");
            }
            found = new IdParameter(parameter.getParameterIndex(), annotation.value());
        }
        return Optional.ofNullable(found);
    }
}
