package com.trust.restclient;

import com.trust.restclient.fixture.wire.WireClient;
import com.trust.restclient.fixture.wire.WirePackageMarker;
import com.trust.restclient.health.ServiceClientCircuitBreakerHealthIndicator;
import com.trust.restclient.tokenrelay.TrustAuthorizedClientManager;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.micrometer.tagged.TaggedCircuitBreakerMetrics;
import io.github.resilience4j.micrometer.tagged.TaggedRetryMetrics;
import io.github.resilience4j.retry.RetryRegistry;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration;
import org.springframework.boot.health.actuate.endpoint.CompositeHealthDescriptor;
import org.springframework.boot.health.actuate.endpoint.HealthDescriptor;
import org.springframework.boot.health.actuate.endpoint.HealthEndpoint;
import org.springframework.boot.health.autoconfigure.actuate.endpoint.HealthEndpointAutoConfiguration;
import org.springframework.boot.health.autoconfigure.registry.HealthContributorRegistryAutoConfiguration;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.restclient.autoconfigure.RestClientAutoConfiguration;
import org.springframework.boot.http.client.autoconfigure.service.HttpServiceClientPropertiesAutoConfiguration;
import org.springframework.boot.restclient.autoconfigure.service.HttpServiceClientAutoConfiguration;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.SecurityFilterChain;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the wiring contract of {@link ServiceClientAutoConfiguration}
 * end-to-end: the shared Resilience4j registries, {@link ServiceClientGroupConfigurer}
 * itself, the metrics binders, and the health indicator - including the
 * isolation (a missing {@link HealthIndicator} on the classpath must not
 * break the rest of this auto-configuration).
 *
 * <p>{@link SslAutoConfiguration} is loaded alongside the native HTTP
 * service client machinery because the group configurer supports mutual TLS
 * through the standard {@code SslBundles} bean - without it, this context
 * would fail for a reason unrelated to what a given test actually verifies.
 * Both are always present in a real Spring Boot application regardless.
 */
class ServiceClientAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withUserConfiguration(WirePackageMarker.class)
            .withConfiguration(AutoConfigurations.of(
                    ServiceClientAutoConfiguration.class, RestClientAutoConfiguration.class,
                    HttpServiceClientAutoConfiguration.class, HttpServiceClientPropertiesAutoConfiguration.class, JacksonAutoConfiguration.class,
                    SslAutoConfiguration.class))
            .withPropertyValues("spring.http.serviceclient.wireClient.base-url=http://127.0.0.1:1");

    @Test
    void whenContextStarts_thenItLoadsSuccessfullyAndTheGroupConfigurerIsPresent() {
        contextRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(ServiceClientGroupConfigurer.class);
            assertThat(context).hasSingleBean(WireClient.class);
        });
    }

    @Test
    void whenContextStarts_thenARetryRegistryAndACircuitBreakerRegistryAreSharedAcrossAllGroups() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(RetryRegistry.class);
            assertThat(context).hasSingleBean(CircuitBreakerRegistry.class);
        });
    }

    @Test
    void givenNoMeterRegistryInTheContext_whenContextStarts_thenNoResilience4jMetricsBinderIsCreated() {
        contextRunner.run(context -> {
            assertThat(context).doesNotHaveBean(TaggedRetryMetrics.class);
            assertThat(context).doesNotHaveBean(TaggedCircuitBreakerMetrics.class);
        });
    }

    @Configuration
    static class CustomRegistriesConfiguration {
        @Bean
        RetryRegistry retryRegistry() {
            return RetryRegistry.ofDefaults();
        }

        @Bean
        CircuitBreakerRegistry circuitBreakerRegistry() {
            return CircuitBreakerRegistry.ofDefaults();
        }
    }

    @Test
    void givenAnApplicationDeclaresItsOwnRegistries_whenContextStarts_thenTheyAreUsedInsteadOfThisStartersDefaults() {
        contextRunner
                .withUserConfiguration(CustomRegistriesConfiguration.class)
                .run(context -> {
                    RetryRegistry ownRetryRegistry =
                            context.getBean(CustomRegistriesConfiguration.class).retryRegistry();
                    CircuitBreakerRegistry ownCircuitBreakerRegistry =
                            context.getBean(CustomRegistriesConfiguration.class).circuitBreakerRegistry();

                    assertThat(context.getBean(RetryRegistry.class)).isSameAs(ownRetryRegistry);
                    assertThat(context.getBean(CircuitBreakerRegistry.class)).isSameAs(ownCircuitBreakerRegistry);

                    // Not just "the bean is kept" - the group actually
                    // registers its named instance into it, on first call.
                    try {
                        context.getBean(WireClient.class).ping();
                    } catch (Exception expected) {
                        // irrelevant here - nothing is listening on 127.0.0.1:1
                    }
                    assertThat(ownRetryRegistry.getAllRetries())
                            .as("the group's retry instance must be registered in the application's own registry")
                            .anyMatch(retry -> retry.getName().equals("wireClient"));
                    assertThat(ownCircuitBreakerRegistry.getAllCircuitBreakers())
                            .as("the group's circuit breaker instance must be registered in the "
                                    + "application's own registry")
                            .anyMatch(cb -> cb.getName().equals("wireClient"));
                });
    }

    @Configuration(proxyBeanMethods = false)
    static class MeterRegistryConfiguration {
        @Bean
        MeterRegistry meterRegistry() {
            return new SimpleMeterRegistry();
        }
    }

    @Test
    void givenARealMeterRegistryInTheContext_whenMakingACall_thenRealResilience4jMetricsAppearInIt() {
        contextRunner
                .withUserConfiguration(MeterRegistryConfiguration.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(TaggedRetryMetrics.class);
                    assertThat(context).hasSingleBean(TaggedCircuitBreakerMetrics.class);

                    RetryRegistry retryRegistry = context.getBean(RetryRegistry.class);
                    retryRegistry.retry("proof-of-binding");

                    MeterRegistry meterRegistry = context.getBean(MeterRegistry.class);
                    assertThat(meterRegistry.getMeters())
                            .as("resilience4j-micrometer must have registered at least one real meter")
                            .isNotEmpty();
                });
    }

    @Test
    void whenContextStarts_thenACircuitBreakerHealthIndicatorIsPresent() {
        contextRunner.run(context -> assertThat(context).hasSingleBean(ServiceClientCircuitBreakerHealthIndicator.class));
    }

    @Test
    void givenHealthExplicitlyDisabled_whenContextStarts_thenNoHealthIndicatorBeanIsCreated() {
        contextRunner
                .withPropertyValues("trust.rest-client.health.enabled=false")
                .run(context -> assertThat(context).doesNotHaveBean(ServiceClientCircuitBreakerHealthIndicator.class));
    }

    @Test
    void givenARealClientWithAnOpenCircuit_whenCheckingHealth_thenItGenuinelyReportsDown() {
        contextRunner
                .withPropertyValues(
                        "trust.rest-client.circuit-breaker.sliding-window-size=1",
                        "trust.rest-client.circuit-breaker.minimum-number-of-calls=1",
                        "trust.rest-client.retry.enabled=false")
                .run(context -> {
                    WireClient client = context.getBean(WireClient.class);
                    // Nothing is listening on 127.0.0.1:1 - a real connection
                    // failure, exactly what should open the circuit for real.
                    try {
                        client.ping();
                    } catch (Exception expected) {
                        // irrelevant here - only the resulting circuit state matters
                    }

                    ServiceClientCircuitBreakerHealthIndicator healthIndicator =
                            context.getBean(ServiceClientCircuitBreakerHealthIndicator.class);
                    assertThat(healthIndicator.health().getStatus()).isEqualTo(Status.DOWN);
                });
    }

    /**
     * Goes through Actuator's own real {@link HealthEndpoint} - not just
     * this starter's health indicator bean in isolation - to verify the
     * component key it actually surfaces under (the bean name minus its
     * {@code HealthIndicator} suffix, per Spring Boot's own convention),
     * since the README documents that exact key.
     */
    @Test
    void whenQueryingTheRealHealthEndpoint_thenTheCircuitBreakerComponentAppearsUnderTheDocumentedKey() {
        contextRunner
                .withConfiguration(AutoConfigurations.of(
                        HealthContributorRegistryAutoConfiguration.class, HealthEndpointAutoConfiguration.class))
                .run(context -> {
                    HealthEndpoint healthEndpoint = context.getBean(HealthEndpoint.class);
                    HealthDescriptor descriptor = healthEndpoint.health();

                    assertThat(descriptor).isInstanceOf(CompositeHealthDescriptor.class);
                    assertThat(((CompositeHealthDescriptor) descriptor).getComponents())
                            .as("the bean name serviceClientCircuitBreakerHealthIndicator must surface as "
                                    + "serviceClientCircuitBreaker")
                            .containsKey("serviceClientCircuitBreaker");
                });
    }

    // ------------------------------------------------------------------
    // Must start without Actuator/Micrometer on the classpath
    // ------------------------------------------------------------------

    @Test
    void givenHealthIndicatorClassAbsentFromTheClasspath_whenContextStarts_thenItStillLoadsSuccessfully() {
        contextRunner
                .withClassLoader(new FilteredClassLoader(HealthIndicator.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(ServiceClientGroupConfigurer.class);
                    assertThat(context).hasSingleBean(WireClient.class);
                    assertThat(context).doesNotHaveBean(ServiceClientCircuitBreakerHealthIndicator.class);
                });
    }

    @Test
    void givenHealthIndicatorClassAbsent_whenMakingACall_thenTheGroupsCapabilitiesStillWork() {
        contextRunner
                .withClassLoader(new FilteredClassLoader(HealthIndicator.class))
                .run(context -> {
                    WireClient client = context.getBean(WireClient.class);
                    // Nothing is listening on 127.0.0.1:1 - the retry/circuit
                    // breaker machinery still runs, health reporting aside.
                    org.assertj.core.api.Assertions.assertThatThrownBy(client::ping);
                    assertThat(context.getBean(CircuitBreakerRegistry.class).getAllCircuitBreakers())
                            .anyMatch(cb -> cb.getName().equals("wireClient"));
                });
    }

    // ------------------------------------------------------------------
    // Autonomous client_credentials OAuth2AuthorizedClientManager
    // ------------------------------------------------------------------

    private static final String M2M_REGISTRATION_PROPERTIES_PREFIX =
            "spring.security.oauth2.client.registration.inventory-m2m.";

    private final ApplicationContextRunner oauth2ClientRunner = contextRunner
            .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class))
            .withPropertyValues(
                    M2M_REGISTRATION_PROPERTIES_PREFIX + "client-id=test-client",
                    M2M_REGISTRATION_PROPERTIES_PREFIX + "client-secret=test-secret",
                    M2M_REGISTRATION_PROPERTIES_PREFIX + "authorization-grant-type=client_credentials",
                    M2M_REGISTRATION_PROPERTIES_PREFIX + "provider=keycloak",
                    "spring.security.oauth2.client.provider.keycloak.token-uri=http://127.0.0.1:1/token");

    @Test
    void givenAClientCredentialsRegistrationAndNoApplicationManager_whenContextStarts_thenTrustCreatesAManager() {
        oauth2ClientRunner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).hasSingleBean(OAuth2AuthorizedClientManager.class);
            assertThat(context.getBean(OAuth2AuthorizedClientManager.class))
                    .isInstanceOf(TrustAuthorizedClientManager.class);
        });
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationSuppliedManagerConfiguration {
        static final OAuth2AuthorizedClientManager CUSTOM_MANAGER = request -> new OAuth2AuthorizedClient(
                ClientRegistration.withRegistrationId(request.getClientRegistrationId())
                        .clientId("test")
                        .tokenUri("http://localhost/token")
                        .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                        .build(),
                "principal",
                new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
                        Instant.now(), Instant.now().plusSeconds(60)));

        @Bean
        OAuth2AuthorizedClientManager authorizedClientManager() {
            return CUSTOM_MANAGER;
        }
    }

    @Test
    void givenAnApplicationSuppliedManager_whenContextStarts_thenTrustsDefaultManagerDoesNotOverrideIt() {
        oauth2ClientRunner
                .withUserConfiguration(ApplicationSuppliedManagerConfiguration.class)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(OAuth2AuthorizedClientManager.class);
                    assertThat(context.getBean(OAuth2AuthorizedClientManager.class))
                            .isSameAs(ApplicationSuppliedManagerConfiguration.CUSTOM_MANAGER);
                });
    }

    @Test
    void givenNoOAuth2ClientRegistrationAtAll_whenContextStarts_thenNoManagerIsCreatedAndNothingFails() {
        contextRunner
                .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(OAuth2AuthorizedClientManager.class);
                });
    }

    @Test
    void givenTrustsDefaultManagerIsActive_whenContextStarts_thenNoSecurityFilterChainIsAdded() {
        oauth2ClientRunner.run(context -> assertThat(context).doesNotHaveBean(SecurityFilterChain.class));
    }
}
