package com.trust.security.core.authorization;

import org.jspecify.annotations.Nullable;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.MethodClassKey;
import org.springframework.core.annotation.AnnotatedElementUtils;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finds the {@link RequiresPermission} that applies to a method: on the
 * method itself first, then on its class. Results are cached - this runs on
 * every call of a secured method.
 */
public final class RequiresPermissionResolver {

    private final Map<MethodClassKey, Optional<RequiresPermission>> cache = new ConcurrentHashMap<>();

    public @Nullable RequiresPermission resolve(Method method, Class<?> targetClass) {
        return cache.computeIfAbsent(new MethodClassKey(method, targetClass),
                key -> Optional.ofNullable(find(method, targetClass))).orElse(null);
    }

    private static @Nullable RequiresPermission find(Method method, Class<?> targetClass) {
        Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);

        RequiresPermission annotation =
                AnnotatedElementUtils.findMergedAnnotation(specificMethod, RequiresPermission.class);
        if (annotation != null) {
            return annotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(targetClass, RequiresPermission.class);
    }
}
