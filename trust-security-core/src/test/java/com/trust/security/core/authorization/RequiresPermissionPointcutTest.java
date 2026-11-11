package com.trust.security.core.authorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class RequiresPermissionPointcutTest {

    @Mock
    private RequiresPermissionResolver resolver;

    static class Target {
        public void doSomething() {
        }
    }

    @RequiresPermission(resource = "orders", scope = "read")
    static class AnnotationSample {
    }

    @Test
    void givenNullResolver_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new RequiresPermissionPointcut(null))
                .withMessage("resolver must not be null");
    }

    @Test
    void givenResolverReturningAnnotation_whenMatching_thenPointcutMatchesAndDelegatesToResolverWithSameArguments() throws Exception {
        Method method = Target.class.getMethod("doSomething");
        RequiresPermission annotation = AnnotationSample.class.getAnnotation(RequiresPermission.class);
        given(resolver.resolve(method, Target.class)).willReturn(annotation);
        RequiresPermissionPointcut pointcut = new RequiresPermissionPointcut(resolver);

        boolean matches = pointcut.matches(method, Target.class);

        assertThat(matches).isTrue();
        verify(resolver).resolve(method, Target.class);
    }

    @Test
    void givenResolverReturningNull_whenMatching_thenPointcutDoesNotMatch() throws Exception {
        Method method = Target.class.getMethod("doSomething");
        given(resolver.resolve(method, Target.class)).willReturn(null);
        RequiresPermissionPointcut pointcut = new RequiresPermissionPointcut(resolver);

        boolean matches = pointcut.matches(method, Target.class);

        assertThat(matches).isFalse();
    }
}
