package com.trust.security.core.acr;

import org.jspecify.annotations.Nullable;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.MethodClassKey;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.util.ConcurrentReferenceHashMap;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;

/**
 * Finds the {@link RequiresAcr} that applies to a method: on the method
 * itself first, then on its class. Results are cached - this runs on every
 * call of a secured method. Soft references: this class lives in a library
 * jar and must not pin application classes across a devtools restart.
 */
final class RequiresAcrResolver {

    private static final Map<MethodClassKey, Optional<RequiresAcr>> CACHE = new ConcurrentReferenceHashMap<>();

    private RequiresAcrResolver() {
    }

    static @Nullable RequiresAcr resolve(Method method, Class<?> targetClass) {
        return CACHE.computeIfAbsent(new MethodClassKey(method, targetClass),
                key -> Optional.ofNullable(find(method, targetClass))).orElse(null);
    }

    private static @Nullable RequiresAcr find(Method method, Class<?> targetClass) {
        Method specificMethod = AopUtils.getMostSpecificMethod(method, targetClass);

        RequiresAcr annotation = AnnotatedElementUtils.findMergedAnnotation(specificMethod, RequiresAcr.class);
        if (annotation != null) {
            return annotation;
        }
        return AnnotatedElementUtils.findMergedAnnotation(targetClass, RequiresAcr.class);
    }
}
