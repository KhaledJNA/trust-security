package com.trust.restclient;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Binding behavior of {@link ServiceClientProperties}, under its
 * {@code trust.rest-client} prefix. Transport (URL, timeouts, TLS) is native
 * configuration under {@code spring.http.serviceclient.<group>.*} and is not
 * this class's concern - see {@code ServiceClientWireCharacterizationTest}
 * for that, exercised end to end.
 */
class ServiceClientPropertiesTest {

    @Configuration
    @EnableConfigurationProperties(ServiceClientProperties.class)
    static class TestConfig {
    }

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner().withUserConfiguration(TestConfig.class);

    @Test
    void givenNoRetryConfigured_whenBinding_thenTheDocumentedDefaultsApply() {
        contextRunner.run(context -> {
            ServiceClientProperties properties = context.getBean(ServiceClientProperties.class);
            assertThat(properties.getRetry().isEnabled()).isTrue();
            assertThat(properties.getRetry().getMaxAttempts()).isEqualTo(3);
            assertThat(properties.getRetry().getWaitDuration()).isEqualTo(Duration.ofMillis(200));
            assertThat(properties.getRetry().getRetryableStatusCodes()).containsExactlyInAnyOrder(502, 503, 504);
        });
    }

    @Test
    void givenNoTokenAcquisitionRetryConfigured_whenBinding_thenTheDocumentedDefaultsApply() {
        contextRunner.run(context -> {
            ServiceClientProperties.TokenAcquisitionRetryProperties tokenAcquisitionRetry =
                    context.getBean(ServiceClientProperties.class).getTokenAcquisitionRetry();
            assertThat(tokenAcquisitionRetry.isEnabled()).isTrue();
            assertThat(tokenAcquisitionRetry.getMaxAttempts()).isEqualTo(3);
            assertThat(tokenAcquisitionRetry.getWaitDuration()).isEqualTo(Duration.ofMillis(200));
        });
    }

    @Test
    void givenTokenAcquisitionRetryConfigured_whenBinding_thenItReplacesTheDefault() {
        contextRunner
                .withPropertyValues(
                        "trust.rest-client.token-acquisition-retry.enabled=false",
                        "trust.rest-client.token-acquisition-retry.max-attempts=5")
                .run(context -> {
                    ServiceClientProperties.TokenAcquisitionRetryProperties tokenAcquisitionRetry =
                            context.getBean(ServiceClientProperties.class).getTokenAcquisitionRetry();
                    assertThat(tokenAcquisitionRetry.isEnabled()).isFalse();
                    assertThat(tokenAcquisitionRetry.getMaxAttempts()).isEqualTo(5);
                });
    }

    @Test
    void givenNoHealthConfigured_whenBinding_thenItDefaultsToEnabled() {
        contextRunner.run(context ->
                assertThat(context.getBean(ServiceClientProperties.class).getHealth().isEnabled()).isTrue());
    }

    @Test
    void givenHealthExplicitlyDisabled_whenBinding_thenItReplacesTheDefault() {
        contextRunner
                .withPropertyValues("trust.rest-client.health.enabled=false")
                .run(context ->
                        assertThat(context.getBean(ServiceClientProperties.class).getHealth().isEnabled()).isFalse());
    }

    @Test
    void givenNoCircuitBreakerConfigured_whenBinding_thenTheDocumentedDefaultsApply() {
        contextRunner.run(context -> {
            ServiceClientProperties.CircuitBreakerProperties circuitBreaker =
                    context.getBean(ServiceClientProperties.class).getCircuitBreaker();
            assertThat(circuitBreaker.isEnabled()).isTrue();
            assertThat(circuitBreaker.getFailureRateThreshold()).isEqualTo(50.0f);
            assertThat(circuitBreaker.getSlidingWindowSize()).isEqualTo(10);
            assertThat(circuitBreaker.getMinimumNumberOfCalls()).isEqualTo(10);
            assertThat(circuitBreaker.getWaitDurationInOpenState()).isEqualTo(Duration.ofSeconds(30));
            assertThat(circuitBreaker.getPermittedNumberOfCallsInHalfOpenState()).isEqualTo(3);
        });
    }

    @Test
    void givenCircuitBreakerExplicitlyDisabledForAGroup_whenResolvingForThatGroupName_thenItIsNotEnabled() {
        contextRunner
                .withPropertyValues("trust.rest-client.groups.flaky-service.circuit-breaker.enabled=false")
                .run(context -> {
                    ServiceClientProperties properties = context.getBean(ServiceClientProperties.class);
                    assertThat(properties.circuitBreakerFor("flaky-service").isEnabled()).isFalse();
                    assertThat(properties.circuitBreakerFor("other-service").isEnabled()).isTrue();
                });
    }

    @Test
    void givenAPerGroupCircuitBreakerOverride_whenResolvingForThatGroupName_thenItReplacesTheSharedDefault() {
        contextRunner
                .withPropertyValues(
                        "trust.rest-client.circuit-breaker.failure-rate-threshold=50",
                        "trust.rest-client.groups.slow-service.circuit-breaker.failure-rate-threshold=75",
                        "trust.rest-client.groups.slow-service.circuit-breaker.sliding-window-size=20")
                .run(context -> {
                    ServiceClientProperties properties = context.getBean(ServiceClientProperties.class);

                    assertThat(properties.circuitBreakerFor("slow-service").getFailureRateThreshold())
                            .isEqualTo(75.0f);
                    assertThat(properties.circuitBreakerFor("slow-service").getSlidingWindowSize()).isEqualTo(20);

                    // A different, unconfigured group is unaffected by slow-service's override.
                    assertThat(properties.circuitBreakerFor("other-service").getFailureRateThreshold())
                            .isEqualTo(50.0f);
                });
    }

    @Test
    void givenRetryExplicitlyDisabledForAGroup_whenResolvingForThatGroupName_thenItIsNotEnabled() {
        contextRunner
                .withPropertyValues("trust.rest-client.groups.flaky-service.retry.enabled=false")
                .run(context -> {
                    ServiceClientProperties properties = context.getBean(ServiceClientProperties.class);
                    assertThat(properties.retryFor("flaky-service").isEnabled()).isFalse();
                    // Unrelated groups keep the shared default (enabled).
                    assertThat(properties.retryFor("other-service").isEnabled()).isTrue();
                });
    }

    @Test
    void givenACustomRetryableStatusSet_whenBinding_thenItReplacesTheDefaultSet() {
        contextRunner
                .withPropertyValues(
                        "trust.rest-client.retry.retryable-status-codes[0]=500",
                        "trust.rest-client.retry.retryable-status-codes[1]=502")
                .run(context -> {
                    ServiceClientProperties properties = context.getBean(ServiceClientProperties.class);
                    assertThat(properties.getRetry().getRetryableStatusCodes()).containsExactlyInAnyOrder(500, 502);
                });
    }

    @Test
    void givenNoPerGroupOverride_whenResolvingForAGroupName_thenTheSharedDefaultsApply() {
        contextRunner
                .withPropertyValues(
                        "trust.rest-client.retry.max-attempts=5",
                        "trust.rest-client.retry.wait-duration=500ms")
                .run(context -> {
                    ServiceClientProperties properties = context.getBean(ServiceClientProperties.class);
                    assertThat(properties.retryFor("unconfigured-group").getMaxAttempts()).isEqualTo(5);
                    assertThat(properties.retryFor("unconfigured-group").getWaitDuration())
                            .isEqualTo(Duration.ofMillis(500));
                });
    }

    @Test
    void givenAPerGroupOverride_whenResolvingForThatGroupName_thenItReplacesTheSharedDefault() {
        contextRunner
                .withPropertyValues(
                        "trust.rest-client.retry.max-attempts=5",
                        "trust.rest-client.groups.slow-service.retry.max-attempts=1")
                .run(context -> {
                    ServiceClientProperties properties = context.getBean(ServiceClientProperties.class);

                    assertThat(properties.retryFor("slow-service").getMaxAttempts()).isEqualTo(1);

                    // A different, unconfigured group is unaffected by slow-service's override.
                    assertThat(properties.retryFor("other-service").getMaxAttempts()).isEqualTo(5);
                });
    }
}
