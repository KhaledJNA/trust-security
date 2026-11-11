package com.trust.restclient.health;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Behavioral tests for {@link ServiceClientCircuitBreakerHealthIndicator}:
 * does {@code /actuator/health} genuinely reflect a real open circuit, and
 * correctly stay {@code UP} otherwise?
 */
class ServiceClientCircuitBreakerHealthIndicatorTest {

    @Test
    void givenNoCircuitBreakersRegisteredYet_whenCheckingHealth_thenItReportsUp() {
        CircuitBreakerRegistry registry = CircuitBreakerRegistry.ofDefaults();
        ServiceClientCircuitBreakerHealthIndicator healthIndicator =
                new ServiceClientCircuitBreakerHealthIndicator(registry);

        assertThat(healthIndicator.health().getStatus()).isEqualTo(Status.UP);
    }

    @Test
    void givenOnlyClosedCircuitBreakers_whenCheckingHealth_thenItReportsUpWithEachStateListed() {
        CircuitBreakerRegistry registry = CircuitBreakerRegistry.ofDefaults();
        registry.circuitBreaker("documentsClient");
        registry.circuitBreaker("downstreamClient");

        Health health = new ServiceClientCircuitBreakerHealthIndicator(registry).health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails())
                .containsEntry("documentsClient", "CLOSED")
                .containsEntry("downstreamClient", "CLOSED");
    }

    @Test
    void givenAnOpenCircuitBreaker_whenCheckingHealth_thenItReportsDownWithThatClientNamedInTheDetails() {
        CircuitBreakerRegistry registry = CircuitBreakerRegistry.ofDefaults();
        registry.circuitBreaker("healthyClient");
        CircuitBreaker strugglingCircuit = registry.circuitBreaker("strugglingClient");
        strugglingCircuit.transitionToOpenState();

        Health health = new ServiceClientCircuitBreakerHealthIndicator(registry).health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
        assertThat(health.getDetails())
                .containsEntry("healthyClient", "CLOSED")
                .containsEntry("strugglingClient", "OPEN");
    }

    @Test
    void givenAHalfOpenCircuitBreaker_whenCheckingHealth_thenItStillReportsUpButListsTheHalfOpenState() {
        CircuitBreakerRegistry registry = CircuitBreakerRegistry.ofDefaults();
        CircuitBreaker circuitBreaker = registry.circuitBreaker("recoveringClient");
        circuitBreaker.transitionToOpenState();
        circuitBreaker.transitionToHalfOpenState();

        Health health = new ServiceClientCircuitBreakerHealthIndicator(registry).health();

        assertThat(health.getStatus())
                .as("a circuit actively testing recovery is not the same as one still rejecting everything")
                .isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("recoveringClient", "HALF_OPEN");
    }
}
