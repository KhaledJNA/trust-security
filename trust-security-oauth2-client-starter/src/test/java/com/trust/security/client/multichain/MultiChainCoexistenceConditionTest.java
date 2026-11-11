package com.trust.security.client.multichain;

import net.bytebuddy.ByteBuddy;
import net.bytebuddy.dynamic.loading.ClassLoadingStrategy;
import org.junit.jupiter.api.Test;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.NestedExceptionUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The resource-server starter is simulated by a class generated at runtime
 * under its auto-configuration's name, visible only to the runner's class
 * loader - so the other tests of this module never see it.
 */
class MultiChainCoexistenceConditionTest {

    private static final String OWN = MultiChainCoexistenceCondition.OWN_REQUEST_PATTERN_PROPERTY;
    private static final String RESOURCE_SERVER = MultiChainCoexistenceCondition.RESOURCE_SERVER_REQUEST_PATTERN_PROPERTY;

    @Configuration(proxyBeanMethods = false)
    @Conditional(MultiChainCoexistenceCondition.class)
    static class GuardedConfiguration {
        @Bean
        String guardedBean() {
            return "active";
        }
    }

    private static ClassLoader classLoaderWithResourceServerStarter() {
        return new ByteBuddy()
                .subclass(Object.class)
                .name(MultiChainCoexistenceCondition.RESOURCE_SERVER_AUTO_CONFIGURATION_CLASS)
                .make()
                .load(MultiChainCoexistenceConditionTest.class.getClassLoader(), ClassLoadingStrategy.Default.WRAPPER)
                .getLoaded()
                .getClassLoader();
    }

    private static Throwable mostSpecificCause(Throwable failure) {
        assertThat(failure).as("startup failure").isNotNull();
        return NestedExceptionUtils.getMostSpecificCause(failure);
    }

    private final ApplicationContextRunner withoutResourceServer = new ApplicationContextRunner()
            .withUserConfiguration(GuardedConfiguration.class);

    private final ApplicationContextRunner withResourceServer = withoutResourceServer
            .withClassLoader(classLoaderWithResourceServerStarter());

    @Test
    void givenResourceServerStarterAbsent_thenMatchesWithoutAnyProperty() {
        withoutResourceServer.run(context -> assertThat(context).hasBean("guardedBean"));
    }

    @Test
    void givenResourceServerStarterPresentAndNoPattern_thenStartupFails() {
        withResourceServer.run(context -> assertThat(mostSpecificCause(context.getStartupFailure()))
                .isInstanceOf(MultiChainConfigurationException.class)
                .hasMessageContaining("not declared on both sides"));
    }

    @Test
    void givenResourceServerStarterPresentAndOnlyOwnPattern_thenStartupFails() {
        withResourceServer
                .withPropertyValues(OWN + "=/app/**")
                .run(context -> assertThat(mostSpecificCause(context.getStartupFailure()))
                        .isInstanceOf(MultiChainConfigurationException.class));
    }

    @Test
    void givenResourceServerStarterPresentAndBlankPattern_thenStartupFails() {
        withResourceServer
                .withPropertyValues(OWN + "= ", RESOURCE_SERVER + "=/api/**")
                .run(context -> assertThat(mostSpecificCause(context.getStartupFailure()))
                        .isInstanceOf(MultiChainConfigurationException.class));
    }

    @Test
    void givenResourceServerStarterPresentAndOverlappingPatterns_thenStartupFailsNamingBoth() {
        withResourceServer
                .withPropertyValues(OWN + "=/**", RESOURCE_SERVER + "=/api/**")
                .run(context -> assertThat(mostSpecificCause(context.getStartupFailure()))
                        .isInstanceOf(MultiChainConfigurationException.class)
                        .hasMessageContaining("'/**'")
                        .hasMessageContaining("'/api/**'"));
    }

    @Test
    void givenResourceServerStarterPresentAndDisjointPatterns_thenMatches() {
        withResourceServer
                .withPropertyValues(OWN + "=/app/**", RESOURCE_SERVER + "=/api/**")
                .run(context -> assertThat(context).hasBean("guardedBean"));
    }

    @Test
    void givenAMultiChainFailure_thenTheAnalyzerReportsDescriptionAndAction() {
        MultiChainConfigurationException failure = MultiChainConfigurationException.overlapping("/**", "/api/**");

        FailureAnalysis analysis = new MultiChainConfigurationFailureAnalyzer().analyze(new RuntimeException(failure));

        assertThat(analysis.getDescription()).isEqualTo(failure.getMessage());
        assertThat(analysis.getAction()).contains("non-overlapping");
    }

    @Test
    void givenResourceServerStarterPresentButItsAutoConfigurationExcluded_thenMatchesWithoutAnyPattern() {
        withResourceServer
                .withPropertyValues("spring.autoconfigure.exclude=" + MultiChainCoexistenceCondition.RESOURCE_SERVER_AUTO_CONFIGURATION_CLASS)
                .run(context -> assertThat(context).hasBean("guardedBean"));
    }
}
