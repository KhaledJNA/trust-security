package com.trust.security.client.tenant;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class RegistrationIdResolutionConfiguredConditionTest {

    @Configuration
    static class ConditionalBeanConfig {

        @Bean
        @Conditional(RegistrationIdResolutionConfiguredCondition.class)
        String marker() {
            return "active";
        }
    }

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(ConditionalBeanConfig.class);

    @Test
    void givenNoRegistrationIdResolutionConfigured_whenContextStarts_thenConditionDoesNotMatch() {
        contextRunner.run(context -> assertThat(context).doesNotHaveBean("marker"));
    }

    @Test
    void givenRegistrationIdResolutionConfigured_whenContextStarts_thenConditionMatches() {
        contextRunner
                .withPropertyValues(
                        "trust.security.oauth2-client.login.registration-id-resolution.request-pattern=/sso/login/{tenant}",
                        "trust.security.oauth2-client.login.registration-id-resolution.source=path",
                        "trust.security.oauth2-client.login.registration-id-resolution.variable-name=tenant",
                        "trust.security.oauth2-client.login.registration-id-resolution.mappings.acme=keycloak-acme")
                .run(context -> assertThat(context).hasBean("marker"));
    }
}
