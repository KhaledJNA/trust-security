package com.trust.restclient;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.trust.restclient.fixture.wire.SharedGroupPackageMarker;
import com.trust.restclient.fixture.wire.WireClientCreds;
import com.trust.restclient.fixture.wire.WireClientCredsPackageMarker;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.autoconfigure.ssl.SslAutoConfiguration;
import org.springframework.boot.http.client.autoconfigure.service.HttpServiceClientPropertiesAutoConfiguration;
import org.springframework.boot.jackson.autoconfigure.JacksonAutoConfiguration;
import org.springframework.boot.restclient.autoconfigure.RestClientAutoConfiguration;
import org.springframework.boot.restclient.autoconfigure.service.HttpServiceClientAutoConfiguration;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Startup guards and the multi-interface group warning implemented by {@link ServiceClientGroupConfigurer}.
 */
class ServiceClientGroupConfigurerTest {

    private final ApplicationContextRunner baseRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                    ServiceClientAutoConfiguration.class, RestClientAutoConfiguration.class,
                    HttpServiceClientAutoConfiguration.class, HttpServiceClientPropertiesAutoConfiguration.class,
                    JacksonAutoConfiguration.class, SslAutoConfiguration.class));

    @Configuration(proxyBeanMethods = false)
    static class ManagerConfiguration {
        @Bean
        OAuth2AuthorizedClientManager authorizedClientManager() {
            return new OAuth2AuthorizedClientManager() {
                @Override
                public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest request) {
                    return new OAuth2AuthorizedClient(
                            ClientRegistration.withRegistrationId(request.getClientRegistrationId())
                                    .clientId("test")
                                    .tokenUri("http://localhost/token")
                                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                                    .build(),
                            "principal",
                            new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, "token",
                                    Instant.now(), Instant.now().plusSeconds(60)));
                }
            };
        }
    }

    @Configuration(proxyBeanMethods = false)
    static class OtherRegistrationOnlyRepositoryConfiguration {
        @Bean
        ClientRegistrationRepository clientRegistrationRepository() {
            return new InMemoryClientRegistrationRepository(
                    ClientRegistration.withRegistrationId("some-other-registration")
                            .clientId("test")
                            .tokenUri("http://localhost/token")
                            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                            .build());
        }
    }

    @Test
    void givenClientRegistrationIdWithNoManagerBean_whenContextStarts_thenItFailsNamingTheInterfaceAndRegistration() {
        baseRunner
                .withUserConfiguration(WireClientCredsPackageMarker.class)
                .withPropertyValues("spring.http.serviceclient.wireClientCreds.base-url=http://127.0.0.1:1")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining(WireClientCreds.class.getName())
                            .hasMessageContaining("keycloak")
                            .hasMessageContaining("OAuth2AuthorizedClientManager");
                });
    }

    @Test
    void givenClientRegistrationIdNamingAnUnknownRegistration_whenContextStarts_thenItFailsNamingTheRegistration() {
        baseRunner
                .withUserConfiguration(WireClientCredsPackageMarker.class, ManagerConfiguration.class,
                        OtherRegistrationOnlyRepositoryConfiguration.class)
                .withPropertyValues("spring.http.serviceclient.wireClientCreds.base-url=http://127.0.0.1:1")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining(WireClientCreds.class.getName())
                            .hasMessageContaining("keycloak");
                });
    }

    @Test
    void givenClientRegistrationIdNamingARealRegistration_whenContextStarts_thenItStartsSuccessfully() {
        baseRunner
                .withUserConfiguration(WireClientCredsPackageMarker.class, ManagerConfiguration.class)
                .withPropertyValues("spring.http.serviceclient.wireClientCreds.base-url=http://127.0.0.1:1")
                .run(context -> assertThat(context).hasNotFailed());
    }

    /**
     * Without this guard, this exact configuration would fail
     * silently at request time instead of at startup - Trust's own
     * {@code client_credentials}-only manager (auto-configured the moment a
     * {@code ClientRegistrationRepository}/{@code OAuth2AuthorizedClientService}
     * pair exists, regardless of that registration's grant type) would be
     * found by the "a manager exists" startup guard, then simply return no
     * authorized client for an {@code authorization_code} registration -
     * abstaining silently rather than failing loudly. This is the guard
     * that turns that into an explicit startup failure instead - see
     * {@code TrustAuthorizedClientManager}'s Javadoc.
     */
    @Test
    void givenClientRegistrationIdNamingANonClientCredentialsRegistration_whenTrustsDefaultManagerIsActive_thenItFailsNamingTheGrantType() {
        baseRunner
                .withConfiguration(AutoConfigurations.of(
                        org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration.class))
                .withUserConfiguration(WireClientCredsPackageMarker.class)
                .withPropertyValues(
                        "spring.http.serviceclient.wireClientCreds.base-url=http://127.0.0.1:1",
                        "spring.security.oauth2.client.registration.keycloak.client-id=test-client",
                        "spring.security.oauth2.client.registration.keycloak.client-secret=test-secret",
                        "spring.security.oauth2.client.registration.keycloak.authorization-grant-type=authorization_code",
                        "spring.security.oauth2.client.registration.keycloak.redirect-uri={baseUrl}/login/oauth2/code/{registrationId}",
                        "spring.security.oauth2.client.registration.keycloak.provider=keycloak",
                        "spring.security.oauth2.client.provider.keycloak.authorization-uri=http://127.0.0.1:1/authorize",
                        "spring.security.oauth2.client.provider.keycloak.token-uri=http://127.0.0.1:1/token")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining(WireClientCreds.class.getName())
                            .hasMessageContaining("keycloak")
                            .hasMessageContaining("authorization_code")
                            .hasMessageContaining("client_credentials");
                });
    }

    private static String[] registrationProperties(String grantType) {
        return new String[] {
                "spring.security.oauth2.client.registration.keycloak.client-id=test-client",
                "spring.security.oauth2.client.registration.keycloak.client-secret=test-secret",
                "spring.security.oauth2.client.registration.keycloak.authorization-grant-type=" + grantType,
                "spring.security.oauth2.client.registration.keycloak.provider=keycloak",
                "spring.security.oauth2.client.provider.keycloak.token-uri=http://127.0.0.1:1/token"
        };
    }

    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    @Test
    void givenClientRegistrationIdNamingATokenExchangeRegistration_whenTrustsDefaultManagerIsActive_thenItStarts() {
        baseRunner
                .withConfiguration(AutoConfigurations.of(
                        org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration.class))
                .withUserConfiguration(WireClientCredsPackageMarker.class)
                .withPropertyValues("spring.http.serviceclient.wireClientCreds.base-url=http://127.0.0.1:1")
                .withPropertyValues(registrationProperties(TOKEN_EXCHANGE))
                .run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void givenNoTokenRelayOnACallUsingATokenExchangeRegistration_whenContextStarts_thenItFailsNamingTheMethod() {
        baseRunner
                .withConfiguration(AutoConfigurations.of(
                        org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration.class))
                .withUserConfiguration(
                        com.trust.restclient.fixture.wire.WireClientNoRelayWithRegistrationPackageMarker.class)
                .withPropertyValues("spring.http.serviceclient.wireClientNoRelay.base-url=http://127.0.0.1:1")
                .withPropertyValues(registrationProperties(TOKEN_EXCHANGE))
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .hasMessageContaining(
                                    com.trust.restclient.fixture.wire.WireClientNoRelayWithRegistration.class.getName() + "#ping")
                            .hasMessageContaining("@NoTokenRelay")
                            .hasMessageContaining("token-exchange");
                });
    }

    @Test
    void givenNoTokenRelayOnACallUsingAClientCredentialsRegistration_whenContextStarts_thenItStarts() {
        baseRunner
                .withConfiguration(AutoConfigurations.of(
                        org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientAutoConfiguration.class))
                .withUserConfiguration(
                        com.trust.restclient.fixture.wire.WireClientNoRelayWithRegistrationPackageMarker.class)
                .withPropertyValues("spring.http.serviceclient.wireClientNoRelay.base-url=http://127.0.0.1:1")
                .withPropertyValues(registrationProperties("client_credentials"))
                .run(context -> assertThat(context).hasNotFailed());
    }

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void attachLogAppender() {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ServiceClientGroupConfigurer.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        logger.addAppender(logAppender);
    }

    @AfterEach
    void detachLogAppender() {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ServiceClientGroupConfigurer.class);
        logger.detachAppender(logAppender);
    }

    @Test
    void givenAGroupWithMultipleInterfaces_whenContextStarts_thenAWarningIsLoggedNamingTheGroupAndInterfaces() {
        baseRunner
                .withUserConfiguration(SharedGroupPackageMarker.class)
                .withPropertyValues("spring.http.serviceclient.sharedGroup.base-url=http://127.0.0.1:1")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(logAppender.list)
                            .as("a WARN log must name the shared group and both interfaces")
                            .anyMatch(event -> event.getLevel() == Level.WARN
                                    && event.getFormattedMessage().contains("sharedGroup")
                                    && event.getFormattedMessage().contains("SharedGroupClientA")
                                    && event.getFormattedMessage().contains("SharedGroupClientB"));
                });
    }

    @Test
    void givenAGroupWithASingleInterface_whenContextStarts_thenNoWarningIsLogged() {
        baseRunner
                .withUserConfiguration(com.trust.restclient.fixture.wire.WirePackageMarker.class)
                .withPropertyValues("spring.http.serviceclient.wireClient.base-url=http://127.0.0.1:1")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(logAppender.list).noneMatch(event -> event.getLevel() == Level.WARN);
                });
    }
}
