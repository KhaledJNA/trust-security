package com.trust.security.web;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.MethodMetadata;
import org.springframework.security.web.SecurityFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Behavioral tests for {@link NoForeignSecurityFilterChainCondition}.
 * <p>
 * Each test evaluates the condition as if it were placed on a specific
 * candidate {@code @Bean SecurityFilterChain} method - identified via a
 * mocked {@link MethodMetadata}, exactly as Spring supplies it for a
 * method-level {@code @Conditional} - against a given set of already
 * registered {@code SecurityFilterChain} bean names.
 */
class NoForeignSecurityFilterChainConditionTest {

    private final NoForeignSecurityFilterChainCondition condition = new NoForeignSecurityFilterChainCondition();

    @Test
    void givenNoSecurityFilterChainBeans_whenEvaluatingResourceServerBean_thenMatches() {
        assertThat(condition.matches(context(), methodNamed("jwtResourceServerFilterChain"))).isTrue();
    }

    @Test
    void givenNoSecurityFilterChainBeans_whenEvaluatingOAuth2ClientBean_thenMatches() {
        assertThat(condition.matches(context(), methodNamed("oauth2ClientFilterChain"))).isTrue();
    }

    @Test
    void givenSiblingStarterBeanOnly_whenEvaluatingResourceServerBean_thenMatches() {
        assertThat(condition.matches(
                context("oauth2ClientFilterChain"),
                methodNamed("jwtResourceServerFilterChain")))
                .isTrue();
    }

    @Test
    void givenSiblingStarterBeanOnly_whenEvaluatingOAuth2ClientBean_thenMatches() {
        assertThat(condition.matches(
                context("multiIssuerResourceServerFilterChain"),
                methodNamed("oauth2ClientFilterChain")))
                .isTrue();
    }

    @Test
    void givenAnotherResourceServerCandidateAlreadyExists_whenEvaluatingResourceServerBean_thenDoesNotMatch() {
        // Same-starter exclusivity must survive: jwt and opaque must never coexist,
        // regardless of whether the sibling oauth2-client starter is also present.
        assertThat(condition.matches(
                context("jwtResourceServerFilterChain"),
                methodNamed("opaqueTokenResourceServerFilterChain")))
                .isFalse();
    }

    @Test
    void givenAnApplicationSuppliedBeanName_whenEvaluatingResourceServerBean_thenDoesNotMatch() {
        assertThat(condition.matches(
                context("mySecurityConfig"),
                methodNamed("jwtResourceServerFilterChain")))
                .isFalse();
    }

    @Test
    void givenAnApplicationSuppliedBeanName_whenEvaluatingOAuth2ClientBean_thenDoesNotMatch() {
        assertThat(condition.matches(
                context("mySecurityConfig"),
                methodNamed("oauth2ClientFilterChain")))
                .isFalse();
    }

    @Test
    void givenNoBeanFactoryAvailable_whenMatching_thenMatches() {
        ConditionContext context = mock(ConditionContext.class);
        when(context.getBeanFactory()).thenReturn(null);

        assertThat(condition.matches(context, methodNamed("jwtResourceServerFilterChain"))).isTrue();
    }

    private static MethodMetadata methodNamed(String methodName) {
        MethodMetadata metadata = mock(MethodMetadata.class);
        when(metadata.getMethodName()).thenReturn(methodName);
        return metadata;
    }

    private static ConditionContext context(String... existingBeanNames) {
        ConfigurableListableBeanFactory beanFactory = mock(ConfigurableListableBeanFactory.class);
        when(beanFactory.getBeanNamesForType(SecurityFilterChain.class, false, false))
                .thenReturn(existingBeanNames);

        ConditionContext context = mock(ConditionContext.class);
        when(context.getBeanFactory()).thenReturn(beanFactory);
        return context;
    }
}
