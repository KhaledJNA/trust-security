package com.trust.security.core.acr;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;

class RequiresAcrPointcutTest {

    @RequiresAcr("urn:acr:mfa")
    static class Annotated {
        public void secured() {
        }
    }

    static class NotAnnotated {
        public void open() {
        }
    }

    private final RequiresAcrPointcut pointcut = new RequiresAcrPointcut();

    @Test
    void givenMethodResolvingToRequiresAcr_whenMatching_thenPointcutMatches() throws Exception {
        Method method = Annotated.class.getMethod("secured");

        boolean matches = pointcut.matches(method, Annotated.class);

        assertThat(matches).isTrue();
    }

    @Test
    void givenMethodWithoutRequiresAcr_whenMatching_thenPointcutDoesNotMatch() throws Exception {
        Method method = NotAnnotated.class.getMethod("open");

        boolean matches = pointcut.matches(method, NotAnnotated.class);

        assertThat(matches).isFalse();
    }
}
