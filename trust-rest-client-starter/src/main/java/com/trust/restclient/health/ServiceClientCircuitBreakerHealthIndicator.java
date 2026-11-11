package com.trust.restclient.health;

import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;

/**
 * Reports {@code DOWN} in {@code /actuator/health} the moment any
 * HTTP service group's circuit breaker is open - so an operator looking
 * at the application's own health first, before ever opening a metrics
 * dashboard, already sees that a downstream dependency is being avoided.
 *
 * <p>Only an {@code OPEN} circuit is treated as unhealthy. A
 * {@code HALF_OPEN} one - already attempting recovery - and a
 * {@code CLOSED} one are both reported as {@code UP}, but every circuit's
 * exact state is always listed in the details regardless, so a transition
 * in progress is still visible without affecting the aggregate status.
 */
public final class ServiceClientCircuitBreakerHealthIndicator implements HealthIndicator {

    private final CircuitBreakerRegistry circuitBreakerRegistry;

    public ServiceClientCircuitBreakerHealthIndicator(CircuitBreakerRegistry circuitBreakerRegistry) {
        this.circuitBreakerRegistry = circuitBreakerRegistry;
    }

    @Override
    public Health health() {
        Iterable<CircuitBreaker> circuitBreakers = circuitBreakerRegistry.getAllCircuitBreakers();

        Health.Builder builder = Health.up();
        boolean anyOpen = false;
        for (CircuitBreaker circuitBreaker : circuitBreakers) {
            builder.withDetail(circuitBreaker.getName(), circuitBreaker.getState().name());
            if (circuitBreaker.getState() == CircuitBreaker.State.OPEN) {
                anyOpen = true;
            }
        }

        if (anyOpen) {
            builder.down();
        }
        return builder.build();
    }
}
