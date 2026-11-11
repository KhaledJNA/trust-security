package com.trust.web.correlation;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableApplicationContext;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the wiring contract of {@link CorrelationIdFilterAutoConfiguration}:
 * the single source of {@link CorrelationIdFilter} registration shared by
 * every Trust starter that needs it.
 */
class CorrelationIdFilterAutoConfigurationTest {

    private final WebApplicationContextRunner webContextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CorrelationIdFilterAutoConfiguration.class));

    private final ApplicationContextRunner nonWebContextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(CorrelationIdFilterAutoConfiguration.class));

    @Test
    void givenServletWebApplication_whenContextStarts_thenFilterIsRegisteredWithHighestPrecedence() {
        webContextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasBean("correlationIdFilterRegistration");

            @SuppressWarnings("unchecked")
            FilterRegistrationBean<CorrelationIdFilter> registration =
                    (FilterRegistrationBean<CorrelationIdFilter>) context.getBean("correlationIdFilterRegistration");

            assertThat(registration.getFilter()).isInstanceOf(CorrelationIdFilter.class);
            assertThat(registration.getOrder()).isEqualTo(Ordered.HIGHEST_PRECEDENCE);
        });
    }

    @Test
    void givenNonWebApplication_whenContextStarts_thenFilterIsNeverRegistered() {
        nonWebContextRunner.run((AssertableApplicationContext context) -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean("correlationIdFilterRegistration");
            assertThat(context.getBeansOfType(FilterRegistrationBean.class)).isEmpty();
        });
    }

    @Test
    void givenApplicationAlreadyDeclaresItsOwnRegistration_whenContextStarts_thenTrustBacksOffAndTheApplicationOneWins() {
        webContextRunner
                .withUserConfiguration(ApplicationOwnedRegistrationConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(FilterRegistrationBean.class);

                    FilterRegistrationBean<?> registration =
                            context.getBean("correlationIdFilterRegistration", FilterRegistrationBean.class);
                    assertThat(registration.getOrder()).isEqualTo(42);
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationOwnedRegistrationConfiguration {

        @Bean
        FilterRegistrationBean<CorrelationIdFilter> correlationIdFilterRegistration() {
            FilterRegistrationBean<CorrelationIdFilter> registration = new FilterRegistrationBean<>();
            registration.setFilter(new CorrelationIdFilter());
            registration.setOrder(42);
            return registration;
        }
    }
}
