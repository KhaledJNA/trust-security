package com.trust.restclient;

import org.jspecify.annotations.Nullable;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Configuration for the capabilities Trust adds on top of the native HTTP
 * service group mechanism ({@code @ImportHttpServices}) - retry, circuit
 * breaker, token-acquisition retry, health. Transport itself (URL, timeouts,
 * redirects, TLS bundle) is native Spring Boot configuration under
 * {@code spring.http.serviceclient.<group>.*} and is not duplicated here.
 *
 * <p>Prefixed {@code trust.rest-client}, next to the {@code trust.security.*}
 * properties of the other Trust modules, so that it cannot be mistaken for
 * a Spring property.
 */
@Validated
@ConfigurationProperties(prefix = "trust.rest-client")
public class ServiceClientProperties {

    /**
     * Default retry behavior for transient failures - a connection-level
     * error or a {@code 502}/{@code 503}/{@code 504} response - applied to
     * every HTTP service group unless overridden for a specific group under
     * {@link #groups}. Never applied to non-idempotent HTTP methods
     * ({@code POST}/{@code PATCH}), since retrying those after a transient
     * failure risks a duplicate side effect on the target service.
     */
    private RetryProperties retry = new RetryProperties();

    /**
     * Default circuit breaker behavior, applied to every HTTP service group
     * unless overridden for a specific group under {@link #groups}. Unlike
     * {@link #retry}, applies to every HTTP method and to calls annotated
     * {@code @NoRetry} alike: whether a call is safe to repeat is a
     * different question from whether it should count toward the target's
     * observed health.
     */
    private CircuitBreakerProperties circuitBreaker = new CircuitBreakerProperties();

    /**
     * Retry behavior specifically for acquiring/refreshing an OAuth2 access
     * token for a call declared {@code @ClientRegistrationId}, or for
     * relaying the current user's own token in BFF mode. Global only, never
     * per-group: it protects against the identity provider being briefly
     * unavailable, which is not a property of any one downstream API.
     * Independent from {@link #retry} and {@link #circuitBreaker}, which are
     * about the downstream API itself.
     */
    private TokenAcquisitionRetryProperties tokenAcquisitionRetry = new TokenAcquisitionRetryProperties();

    /**
     * The {@code /actuator/health} indicator reporting {@code DOWN} the
     * moment any group's circuit breaker is open. Global only: it reports
     * on every group at once, so there is no single group to scope it to.
     */
    private HealthProperties health = new HealthProperties();

    /**
     * Per-group overrides of {@link #retry}/{@link #circuitBreaker}, keyed
     * by the HTTP service group name ({@code @ImportHttpServices(group=...)}).
     * A field left unset on an entry here falls back to the corresponding
     * top-level default.
     */
    private Map<String, GroupOverrides> groups = new LinkedHashMap<>();

    public RetryProperties getRetry() {
        return retry;
    }

    public void setRetry(RetryProperties retry) {
        this.retry = retry;
    }

    public CircuitBreakerProperties getCircuitBreaker() {
        return circuitBreaker;
    }

    public void setCircuitBreaker(CircuitBreakerProperties circuitBreaker) {
        this.circuitBreaker = circuitBreaker;
    }

    public TokenAcquisitionRetryProperties getTokenAcquisitionRetry() {
        return tokenAcquisitionRetry;
    }

    public void setTokenAcquisitionRetry(TokenAcquisitionRetryProperties tokenAcquisitionRetry) {
        this.tokenAcquisitionRetry = tokenAcquisitionRetry;
    }

    public HealthProperties getHealth() {
        return health;
    }

    public void setHealth(HealthProperties health) {
        this.health = health;
    }

    public Map<String, GroupOverrides> getGroups() {
        return groups;
    }

    public void setGroups(Map<String, GroupOverrides> groups) {
        this.groups = groups;
    }

    /** The retry behavior to use for {@code groupName}: its own override if declared, otherwise the shared default. */
    public RetryProperties retryFor(String groupName) {
        GroupOverrides overrides = groups.get(groupName);
        return overrides != null && overrides.getRetry() != null
                ? overrides.getRetry() : retry;
    }

    /** The circuit breaker behavior to use for {@code groupName}: its own override if declared, otherwise the shared default. */
    public CircuitBreakerProperties circuitBreakerFor(String groupName) {
        GroupOverrides overrides = groups.get(groupName);
        return overrides != null && overrides.getCircuitBreaker() != null
                ? overrides.getCircuitBreaker() : circuitBreaker;
    }

    public static class RetryProperties {

        /**
         * Whether a transient failure on this group is retried at all.
         * Optional: defaults to {@code true}. Set to {@code false} to
         * disable retrying explicitly - preferred over setting
         * {@link #maxAttempts} to {@code 1} to express that intent, since
         * the latter reads as a low retry budget rather than "no retry".
         */
        private boolean enabled = true;

        /**
         * Maximum number of attempts for a single call, including the first
         * one - {@code 1} disables retrying (equivalent to {@code enabled=false}).
         * Optional: defaults to 3.
         */
        private int maxAttempts = 3;

        /**
         * Fixed delay observed between two attempts. Optional: defaults to
         * 200 milliseconds.
         */
        private Duration waitDuration = Duration.ofMillis(200);

        /**
         * HTTP response status codes considered transient and therefore
         * worth retrying. Optional: defaults to {@code 502}, {@code 503}
         * and {@code 504} - the statuses that typically indicate a
         * temporary unavailability of the target service rather than a
         * client-side or application-level error.
         */
        private Set<Integer> retryableStatusCodes = Set.of(502, 503, 504);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public Duration getWaitDuration() {
            return waitDuration;
        }

        public void setWaitDuration(Duration waitDuration) {
            this.waitDuration = waitDuration;
        }

        public Set<Integer> getRetryableStatusCodes() {
            return retryableStatusCodes;
        }

        public void setRetryableStatusCodes(Set<Integer> retryableStatusCodes) {
            this.retryableStatusCodes = retryableStatusCodes;
        }
    }

    public static class CircuitBreakerProperties {

        /**
         * Whether calls to this group are protected by a circuit breaker
         * at all. Optional: defaults to {@code true}.
         */
        private boolean enabled = true;

        /**
         * The percentage of calls in the sliding window that must have
         * failed for the circuit to open. Optional: defaults to 50%.
         */
        private float failureRateThreshold = 50.0f;

        /**
         * Number of calls used to compute the failure rate. Optional:
         * defaults to 10.
         */
        private int slidingWindowSize = 10;

        /**
         * Minimum number of calls required (per sliding window) before the
         * failure rate is evaluated at all - avoids opening the circuit on
         * a handful of unlucky early calls. Optional: defaults to 10. Must
         * not exceed {@link #slidingWindowSize}.
         */
        private int minimumNumberOfCalls = 10;

        /**
         * How long the circuit stays open - rejecting calls immediately,
         * without attempting them - before allowing a limited number of
         * trial calls through to test whether the target has recovered.
         * Optional: defaults to 30 seconds.
         */
        private Duration waitDurationInOpenState = Duration.ofSeconds(30);

        /**
         * Number of trial calls allowed through while the circuit is
         * half-open (testing recovery) before deciding whether to close it
         * again or re-open it. Optional: defaults to 3.
         */
        private int permittedNumberOfCallsInHalfOpenState = 3;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public float getFailureRateThreshold() {
            return failureRateThreshold;
        }

        public void setFailureRateThreshold(float failureRateThreshold) {
            this.failureRateThreshold = failureRateThreshold;
        }

        public int getSlidingWindowSize() {
            return slidingWindowSize;
        }

        public void setSlidingWindowSize(int slidingWindowSize) {
            this.slidingWindowSize = slidingWindowSize;
        }

        public int getMinimumNumberOfCalls() {
            return minimumNumberOfCalls;
        }

        public void setMinimumNumberOfCalls(int minimumNumberOfCalls) {
            this.minimumNumberOfCalls = minimumNumberOfCalls;
        }

        public Duration getWaitDurationInOpenState() {
            return waitDurationInOpenState;
        }

        public void setWaitDurationInOpenState(Duration waitDurationInOpenState) {
            this.waitDurationInOpenState = waitDurationInOpenState;
        }

        public int getPermittedNumberOfCallsInHalfOpenState() {
            return permittedNumberOfCallsInHalfOpenState;
        }

        public void setPermittedNumberOfCallsInHalfOpenState(int permittedNumberOfCallsInHalfOpenState) {
            this.permittedNumberOfCallsInHalfOpenState = permittedNumberOfCallsInHalfOpenState;
        }
    }

    public static class TokenAcquisitionRetryProperties {

        /**
         * Whether acquiring/refreshing an OAuth2 access token is retried at
         * all on a transient identity-provider failure. Optional: defaults
         * to {@code true}.
         */
        private boolean enabled = true;

        /**
         * Maximum number of attempts, including the first one. Optional:
         * defaults to 3.
         */
        private int maxAttempts = 3;

        /**
         * Fixed delay observed between two attempts. Optional: defaults to
         * 200 milliseconds.
         */
        private Duration waitDuration = Duration.ofMillis(200);

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public int getMaxAttempts() {
            return maxAttempts;
        }

        public void setMaxAttempts(int maxAttempts) {
            this.maxAttempts = maxAttempts;
        }

        public Duration getWaitDuration() {
            return waitDuration;
        }

        public void setWaitDuration(Duration waitDuration) {
            this.waitDuration = waitDuration;
        }
    }

    public static class HealthProperties {

        /**
         * Whether the {@code /actuator/health} circuit breaker indicator is
         * registered at all. Optional: defaults to {@code true}. Has no
         * effect if Actuator's health API isn't on the classpath - this
         * starter never requires Actuator itself.
         */
        private boolean enabled = true;

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }
    }

    public static class GroupOverrides {

        /** Unset by default: {@code null} here means "no override, use the shared default". */
        private @Nullable RetryProperties retry;

        /** Unset by default: {@code null} here means "no override, use the shared default". */
        private @Nullable CircuitBreakerProperties circuitBreaker;

        public @Nullable RetryProperties getRetry() {
            return retry;
        }

        public void setRetry(@Nullable RetryProperties retry) {
            this.retry = retry;
        }

        public @Nullable CircuitBreakerProperties getCircuitBreaker() {
            return circuitBreaker;
        }

        public void setCircuitBreaker(@Nullable CircuitBreakerProperties circuitBreaker) {
            this.circuitBreaker = circuitBreaker;
        }
    }
}
