package com.trust.security.core.authorization;

import org.junit.jupiter.api.Test;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class RequiresPermissionResolverTest {

    @RequiresPermission(resource = "orders", scope = "class-level")
    static class ClassLevelAnnotated {
        public void doSomething() {
        }
    }

    static class MethodLevelAnnotated {
        @RequiresPermission(resource = "orders", scope = "read")
        public void doSomething() {
        }
    }

    static class NotAnnotated {
        public void doSomething() {
        }
    }

    @Retention(RetentionPolicy.RUNTIME)
    @Target(ElementType.METHOD)
    @RequiresPermission(resource = "orders", scope = "meta")
    @interface RequiresOrderRead {
    }

    static class MetaAnnotated {
        @RequiresOrderRead
        public void doSomething() {
        }
    }

    interface Operation {
        void doSomething();
    }

    static class MostSpecificMethodOverride implements Operation {
        @Override
        @RequiresPermission(resource = "orders", scope = "impl-level")
        public void doSomething() {
        }
    }

    private final RequiresPermissionResolver resolver = new RequiresPermissionResolver();

    private static Method methodOf(Class<?> type, String name) throws NoSuchMethodException {
        return type.getMethod(name);
    }

    @Test
    void givenMethodLevelAnnotation_whenResolving_thenAnnotationIsReturned() throws Exception {
        Method method = methodOf(MethodLevelAnnotated.class, "doSomething");

        RequiresPermission resolved = resolver.resolve(method, MethodLevelAnnotated.class);

        assertThat(resolved).isNotNull();
        assertThat(resolved.resource()).isEqualTo("orders");
        assertThat(resolved.scope()).isEqualTo("read");
    }

    @Test
    void givenClassLevelAnnotationOnly_whenResolving_thenAnnotationIsReturned() throws Exception {
        Method method = methodOf(ClassLevelAnnotated.class, "doSomething");

        RequiresPermission resolved = resolver.resolve(method, ClassLevelAnnotated.class);

        assertThat(resolved).isNotNull();
        assertThat(resolved.scope()).isEqualTo("class-level");
    }

    @Test
    void givenNoAnnotationAtAll_whenResolving_thenNullIsReturned() throws Exception {
        Method method = methodOf(NotAnnotated.class, "doSomething");

        RequiresPermission resolved = resolver.resolve(method, NotAnnotated.class);

        assertThat(resolved).isNull();
    }

    @Test
    void givenMetaAnnotatedMethod_whenResolving_thenMergedAnnotationIsReturned() throws Exception {
        Method method = methodOf(MetaAnnotated.class, "doSomething");

        RequiresPermission resolved = resolver.resolve(method, MetaAnnotated.class);

        assertThat(resolved).isNotNull();
        assertThat(resolved.scope()).isEqualTo("meta");
    }

    @Test
    void givenInterfaceMethodOverriddenWithAnnotationOnImplementation_whenResolving_thenMostSpecificMethodAnnotationIsUsed() throws Exception {
        Method interfaceMethod = methodOf(Operation.class, "doSomething");

        RequiresPermission resolved = resolver.resolve(interfaceMethod, MostSpecificMethodOverride.class);

        assertThat(resolved).isNotNull();
        assertThat(resolved.scope()).isEqualTo("impl-level");
    }
}
