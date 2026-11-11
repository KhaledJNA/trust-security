package com.trust.security.resourceserver.multichain;

import org.junit.jupiter.api.Test;
import org.springframework.boot.diagnostics.FailureAnalysis;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.NestedExceptionUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The OAuth2 client starter is a real test dependency of this module: it is
 * present by default, and hidden with a {@link FilteredClassLoader} for the
 * "absent" case.
 */
class MultiChainCoexistenceConditionTest {

    private static final String OWN = MultiChainCoexistenceCondition.OWN_REQUEST_PATTERN_PROPERTY;
    private static final String OAUTH2_CLIENT = MultiChainCoexistenceCondition.OAUTH2_CLIENT_REQUEST_PATTERN_PROPERTY;

    @Configuration(proxyBeanMethods = false)
    @Conditional(MultiChainCoexistenceCondition.class)
    static class GuardedConfiguration {
        @Bean
        String guardedBean() {
            return "active";
        }
    }

    private static Throwable mostSpecificCause(Throwable failure) {
        assertThat(failure).as("startup failure").isNotNull();
        return NestedExceptionUtils.getMostSpecificCause(failure);
    }

    private final ApplicationContextRunner withOAuth2Client = new ApplicationContextRunner()
            .withUserConfiguration(GuardedConfiguration.class);

    private final ApplicationContextRunner withoutOAuth2Client = withOAuth2Client
            .withClassLoader(new FilteredClassLoader(MultiChainCoexistenceCondition.OAUTH2_CLIENT_AUTO_CONFIGURATION_CLASS));

    @Test
    void givenOAuth2ClientStarterAbsent_thenMatchesWithoutAnyProperty() {
        withoutOAuth2Client.run(context -> assertThat(context).hasBean("guardedBean"));
    }

    @Test
    void givenOAuth2ClientStarterPresentAndNoPattern_thenStartupFails() {
        withOAuth2Client.run(context -> assertThat(mostSpecificCause(context.getStartupFailure()))
                .isInstanceOf(MultiChainConfigurationException.class)
                .hasMessageContaining("not declared on both sides"));
    }

    @Test
    void givenOAuth2ClientStarterPresentAndOnlyOwnPattern_thenStartupFails() {
        withOAuth2Client
                .withPropertyValues(OWN + "=/api/**")
                .run(context -> assertThat(mostSpecificCause(context.getStartupFailure()))
                        .isInstanceOf(MultiChainConfigurationException.class));
    }

    @Test
    void givenOAuth2ClientStarterPresentAndBlankPattern_thenStartupFails() {
        withOAuth2Client
                .withPropertyValues(OWN + "= ", OAUTH2_CLIENT + "=/app/**")
                .run(context -> assertThat(mostSpecificCause(context.getStartupFailure()))
                        .isInstanceOf(MultiChainConfigurationException.class));
    }

    @Test
    void givenOAuth2ClientStarterPresentAndOverlappingPatterns_thenStartupFailsNamingBoth() {
        withOAuth2Client
                .withPropertyValues(OWN + "=/**", OAUTH2_CLIENT + "=/api/**")
                .run(context -> assertThat(mostSpecificCause(context.getStartupFailure()))
                        .isInstanceOf(MultiChainConfigurationException.class)
                        .hasMessageContaining("'/**'")
                        .hasMessageContaining("'/api/**'"));
    }

    @Test
    void givenOAuth2ClientStarterPresentAndDisjointPatterns_thenMatches() {
        withOAuth2Client
                .withPropertyValues(OWN + "=/api/**", OAUTH2_CLIENT + "=/app/**")
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
    void givenOAuth2ClientStarterPresentButItsAutoConfigurationExcluded_thenMatchesWithoutAnyPattern() {
        withOAuth2Client
                .withPropertyValues("spring.autoconfigure.exclude=" + MultiChainCoexistenceCondition.OAUTH2_CLIENT_AUTO_CONFIGURATION_CLASS)
                .run(context -> assertThat(context).hasBean("guardedBean"));
    }
}
