package com.trust.restclient;

import com.trust.restclient.health.ServiceClientCircuitBreakerHealthIndicator;
import com.trust.restclient.tokenrelay.TrustAuthorizedClientManager;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.micrometer.tagged.TaggedCircuitBreakerMetrics;
import io.github.resilience4j.micrometer.tagged.TaggedRetryMetrics;
import io.github.resilience4j.retry.RetryRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.observation.ObservationRegistry;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;
import tools.jackson.databind.ObjectMapper;

/**
 * Poses Trust's capabilities (token relay, correlation, retry, circuit
 * breaker, unified errors, observation) onto every native HTTP service group
 * ({@code @ImportHttpServices}), via {@link ServiceClientGroupConfigurer}.
 * Transport (URL, timeouts, TLS) is left entirely to the native
 * {@code spring.http.serviceclient.<group>.*} mechanism - this
 * auto-configuration does not build or own any {@code RestClient} itself.
 *
 * <p>Each bean depending on an optional library (Actuator's
 * {@link HealthIndicator}, Micrometer's tagged-metrics binders) is isolated
 * in its own nested {@link Configuration} class, guarded by its own
 * {@link ConditionalOnClass} - see {@link HealthConfiguration} and
 * {@link MetricsConfiguration} for why this isolation, rather than a
 * single flat class, is what actually makes Actuator optional.
 * <p>
 * {@code after = OAuth2ClientAutoConfiguration.class}: {@link
 * #clientCredentialsAuthorizedClientManager} is gated by {@code @ConditionalOnBean}
 * on beans Boot's own {@code OAuth2ClientAutoConfiguration} contributes
 * ({@link ClientRegistrationRepository}, {@link OAuth2AuthorizedClientService}) -
 * without this ordering hint, {@code @ConditionalOnBean} could evaluate
 * before that auto-configuration has registered them, and never see them at
 * all. Safe to reference directly (not behind {@code @ConditionalOnClass}):
 * {@code spring-boot-starter-security-oauth2-client} is a required,
 * non-optional dependency of this starter.
 */
@AutoConfiguration(after = OAuth2ClientAutoConfiguration.class)
@EnableConfigurationProperties(ServiceClientProperties.class)
public class ServiceClientAutoConfiguration {

    /**
     * Shared across every group's retry interceptor, so that
     * {@link MetricsConfiguration#serviceClientRetryMetrics} can expose
     * all of them through one binder. Overridable by declaring an
     * application's own {@code RetryRegistry} bean.
     */
    @Bean
    @ConditionalOnMissingBean
    public RetryRegistry retryRegistry() {
        return RetryRegistry.ofDefaults();
    }

    /** Same reasoning as {@link #retryRegistry()}, for circuit breakers. */
    @Bean
    @ConditionalOnMissingBean
    public CircuitBreakerRegistry circuitBreakerRegistry() {
        return CircuitBreakerRegistry.ofDefaults();
    }

    @Bean
    @ConditionalOnMissingBean
    public ServiceClientGroupConfigurer serviceClientGroupConfigurer(
            ServiceClientProperties properties,
            RetryRegistry retryRegistry,
            CircuitBreakerRegistry circuitBreakerRegistry,
            ObjectMapper objectMapper,
            ObjectProvider<ObservationRegistry> observationRegistryProvider,
            ObjectProvider<OAuth2AuthorizedClientManager> authorizedClientManagerProvider,
            ObjectProvider<ClientRegistrationRepository> clientRegistrationRepositoryProvider,
            ObjectProvider<OAuth2AuthorizedClientService> authorizedClientServiceProvider) {

        return new ServiceClientGroupConfigurer(
                properties, retryRegistry, circuitBreakerRegistry, objectMapper,
                observationRegistryProvider.getIfAvailable(() -> ObservationRegistry.NOOP),
                authorizedClientManagerProvider, clientRegistrationRepositoryProvider,
                authorizedClientServiceProvider);
    }

    /**
     * Trust's default {@code OAuth2AuthorizedClientManager} for
     * {@code @ClientRegistrationId} calls on a {@code client_credentials}
     * registration (autonomous machine-to-machine calls) or a
     * {@code token-exchange} registration (RFC 8693, on behalf of the
     * incoming user) - an application declaring only those needs no manager
     * of its own. Backed by {@link TrustAuthorizedClientManager}, which wraps
     * the standard {@code AuthorizedClientServiceOAuth2AuthorizedClientManager}
     * (works with no {@code HttpServletRequest} at all, unlike the
     * request-bound {@code DefaultOAuth2AuthorizedClientManager} a BFF would
     * use) with a provider chain limited to those two grant types.
     * <p>
     * {@code spring-security-oauth2-client} is a required (non-optional)
     * dependency of this starter, so {@link ClientRegistrationRepository}/
     * {@link OAuth2AuthorizedClientService} are always on the classpath -
     * only {@code @ConditionalOnBean} is needed, not {@code @ConditionalOnClass}
     * (no optional-dependency risk here). Both beans are
     * auto-configured by Spring Boot itself the moment any
     * {@code spring.security.oauth2.client.registration.*} exists,
     * regardless of its grant type - an application with none at all (a
     * pure resource server with no outbound OAuth2 calls) gets neither, so
     * this bean never activates for it, and no {@code SecurityFilterChain}/
     * {@code formLogin()}/{@code httpBasic()} is ever added by this class.
     * {@code @ConditionalOnMissingBean(OAuth2AuthorizedClientManager.class)}
     * keeps an application-supplied manager (a BFF's own, or any other)
     * strictly prioritary - this bean never overrides one.
     */
    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizedClientManager.class)
    @ConditionalOnBean({ClientRegistrationRepository.class, OAuth2AuthorizedClientService.class})
    public OAuth2AuthorizedClientManager clientCredentialsAuthorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) {

        return new TrustAuthorizedClientManager(clientRegistrationRepository, authorizedClientService);
    }

    /**
     * Isolated from the enclosing class so that a missing {@code HealthIndicator}
     * on the classpath (Actuator absent) cannot break reflective
     * introspection of any other bean method here - see this class's own
     * Javadoc.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(HealthIndicator.class)
    static class HealthConfiguration {

        /**
         * Reports {@code DOWN} in {@code /actuator/health} the moment any
         * group's circuit breaker is open - unless explicitly disabled via
         * {@code trust.rest-client.health.enabled=false}.
         */
        @Bean
        @ConditionalOnProperty(prefix = "trust.rest-client.health", name = "enabled", havingValue = "true", matchIfMissing = true)
        @ConditionalOnMissingBean
        ServiceClientCircuitBreakerHealthIndicator serviceClientCircuitBreakerHealthIndicator(
                CircuitBreakerRegistry circuitBreakerRegistry) {
            return new ServiceClientCircuitBreakerHealthIndicator(circuitBreakerRegistry);
        }
    }

    /**
     * Isolated for the same reason as {@link HealthConfiguration}: a
     * missing {@link MeterRegistry} (no Micrometer registry bean, whether or
     * not the class itself is on the classpath) must not affect any other
     * bean method's reflective introspection.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(MeterRegistry.class)
    static class MetricsConfiguration {

        /**
         * Exposes {@code resilience4j.retry.calls} (and related) metrics for
         * every group, tagged by group name - only when the application
         * actually has a real {@link MeterRegistry} bean (typically via
         * Actuator + Micrometer). Without one, this bean is never created:
         * this starter never requires Actuator itself.
         */
        @Bean
        @ConditionalOnBean(MeterRegistry.class)
        TaggedRetryMetrics serviceClientRetryMetrics(RetryRegistry retryRegistry, MeterRegistry meterRegistry) {
            TaggedRetryMetrics metrics = TaggedRetryMetrics.ofRetryRegistry(retryRegistry);
            metrics.bindTo(meterRegistry);
            return metrics;
        }

        /** Same reasoning as {@link #serviceClientRetryMetrics}, exposing {@code resilience4j.circuitbreaker.*} metrics and state. */
        @Bean
        @ConditionalOnBean(MeterRegistry.class)
        TaggedCircuitBreakerMetrics serviceClientCircuitBreakerMetrics(
                CircuitBreakerRegistry circuitBreakerRegistry, MeterRegistry meterRegistry) {
            TaggedCircuitBreakerMetrics metrics = TaggedCircuitBreakerMetrics.ofCircuitBreakerRegistry(circuitBreakerRegistry);
            metrics.bindTo(meterRegistry);
            return metrics;
        }
    }
}
