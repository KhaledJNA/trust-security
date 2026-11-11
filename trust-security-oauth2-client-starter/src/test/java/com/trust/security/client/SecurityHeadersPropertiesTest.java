package com.trust.security.client;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class SecurityHeadersPropertiesTest {

    @Configuration
    @EnableConfigurationProperties(SecurityHeadersProperties.class)
    static class TestConfig {
    }

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner().withUserConfiguration(TestConfig.class);

    @Test
    void givenNoPropertiesConfigured_whenBinding_thenCspIsDisabledByDefaultWithADefaultPolicy() {
        contextRunner.run(context -> {
            SecurityHeadersProperties properties = context.getBean(SecurityHeadersProperties.class);
            assertThat(properties.getContentSecurityPolicy().isEnabled()).isFalse();
            assertThat(properties.getContentSecurityPolicy().getPolicy()).isNotBlank();
        });
    }

    @Test
    void givenEnabledConfigured_whenBinding_thenItIsReflected() {
        contextRunner
                .withPropertyValues("trust.security.oauth2-client.headers.content-security-policy.enabled=true")
                .run(context -> {
                    SecurityHeadersProperties properties = context.getBean(SecurityHeadersProperties.class);
                    assertThat(properties.getContentSecurityPolicy().isEnabled()).isTrue();
                });
    }

    @Test
    void givenCustomPolicyConfigured_whenBinding_thenItReplacesTheDefault() {
        contextRunner
                .withPropertyValues("trust.security.oauth2-client.headers.content-security-policy.policy=default-src 'none'")
                .run(context -> {
                    SecurityHeadersProperties properties = context.getBean(SecurityHeadersProperties.class);
                    assertThat(properties.getContentSecurityPolicy().getPolicy()).isEqualTo("default-src 'none'");
                });
    }
}
