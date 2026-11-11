package com.trust.security.core.acr;

import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link RequiresAcrResolver} is package-private: it is only ever used through
 * {@link RequiresAcrPointcut} and {@link RequiresAcrAuthorizationManager}, but its
 * annotation-resolution contract (method-level, class-level, meta-annotation,
 * most-specific-method) is precise enough to deserve its own direct tests.
 */
class RequiresAcrResolverTest {

    @RequiresAcr("urn:acr:class-level")
    static class ClassLevelAnnotated {
        public void doSomething() {
        }
    }

    static class MethodLevelAnnotated {
        @RequiresAcr("urn:acr:method-level")
        public void doSomething() {
        }
    }

    static class NotAnnotated {
        public void doSomething() {
        }
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @RequiresAcr("urn:acr:meta")
    @interface RequiresMfaAcr {
    }

    static class MetaAnnotated {
        @RequiresMfaAcr
        public void doSomething() {
        }
    }

    interface Operation {
        void doSomething();
    }

    static class MostSpecificMethodOverride implements Operation {
        @Override
        @RequiresAcr("urn:acr:impl-level")
        public void doSomething() {
        }
    }

    private static Method methodOf(Class<?> type, String name) throws NoSuchMethodException {
        return type.getMethod(name);
    }

    @Test
    void givenMethodLevelAnnotation_whenResolving_thenAnnotationIsReturned() throws Exception {
        Method method = methodOf(MethodLevelAnnotated.class, "doSomething");

        RequiresAcr resolved = RequiresAcrResolver.resolve(method, MethodLevelAnnotated.class);

        assertThat(resolved).isNotNull();
        assertThat(resolved.value()).isEqualTo("urn:acr:method-level");
    }

    @Test
    void givenClassLevelAnnotationOnly_whenResolving_thenAnnotationIsReturned() throws Exception {
        Method method = methodOf(ClassLevelAnnotated.class, "doSomething");

        RequiresAcr resolved = RequiresAcrResolver.resolve(method, ClassLevelAnnotated.class);

        assertThat(resolved).isNotNull();
        assertThat(resolved.value()).isEqualTo("urn:acr:class-level");
    }

    @Test
    void givenNoAnnotationAtAll_whenResolving_thenNullIsReturned() throws Exception {
        Method method = methodOf(NotAnnotated.class, "doSomething");

        RequiresAcr resolved = RequiresAcrResolver.resolve(method, NotAnnotated.class);

        assertThat(resolved).isNull();
    }

    @Test
    void givenMetaAnnotatedMethod_whenResolving_thenMergedAnnotationIsReturned() throws Exception {
        Method method = methodOf(MetaAnnotated.class, "doSomething");

        RequiresAcr resolved = RequiresAcrResolver.resolve(method, MetaAnnotated.class);

        assertThat(resolved).isNotNull();
        assertThat(resolved.value()).isEqualTo("urn:acr:meta");
    }

    @Test
    void givenInterfaceMethodOverriddenWithAnnotationOnImplementation_whenResolving_thenMostSpecificMethodAnnotationIsUsed() throws Exception {
        Method interfaceMethod = methodOf(Operation.class, "doSomething");

        RequiresAcr resolved = RequiresAcrResolver.resolve(interfaceMethod, MostSpecificMethodOverride.class);

        assertThat(resolved).isNotNull();
        assertThat(resolved.value()).isEqualTo("urn:acr:impl-level");
    }
}
