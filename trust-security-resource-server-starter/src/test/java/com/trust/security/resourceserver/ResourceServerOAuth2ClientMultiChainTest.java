package com.trust.security.resourceserver;

import com.trust.security.client.OAuth2ClientAutoConfiguration;
import com.trust.security.resourceserver.multichain.MultiChainConfigurationException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.assertj.AssertableWebApplicationContext;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Both Trust security starters in one application: startup fails unless
 * multiple-SecurityFilterChain mode is declared on both sides with disjoint
 * patterns. Each starter has its own {@code MultiChainConfigurationException}
 * (no compile-time coupling between them); whichever condition Spring
 * evaluates first throws, so the tests accept either. Both orders of
 * {@link AutoConfigurations#of} are exercised to show the verdict does not
 * depend on evaluation order.
 */
class ResourceServerOAuth2ClientMultiChainTest {

    private static final String CLIENT_ID_PROPERTY = "trust.security.resource-server.client-id=sample-api";
    private static final String POST_LOGOUT_REDIRECT_URI_PROPERTY =
            "trust.security.post-logout-redirect-uri=http://127.0.0.1:8081/";

    private static ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("test-client")
                .clientId("my-app")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://idp.example.com/auth")
                .tokenUri("https://idp.example.com/token")
                .userNameAttributeName("sub")
                .clientName("test-client")
                .scope("openid")
                .build();
    }

    private WebApplicationContextRunner baseRunner() {
        return new WebApplicationContextRunner()
                .withBean(JwtDecoder.class, () -> mock(JwtDecoder.class))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withBean(ClientRegistrationRepository.class,
                        () -> new InMemoryClientRegistrationRepository(clientRegistration()))
                .withPropertyValues(CLIENT_ID_PROPERTY, POST_LOGOUT_REDIRECT_URI_PROPERTY);
    }

    @Test
    void givenResourceServerAutoConfigurationEvaluatedFirst_thenStartupFailsNamingBothStarters() {
        baseRunner()
                .withConfiguration(AutoConfigurations.of(
                        ResourceServerAutoConfiguration.class,
                        OAuth2ClientAutoConfiguration.class))
                .run(this::assertFailedNamingBothStarters);
    }

    @Test
    void givenOAuth2ClientAutoConfigurationEvaluatedFirst_thenStartupFailsNamingBothStarters() {
        baseRunner()
                .withConfiguration(AutoConfigurations.of(
                        OAuth2ClientAutoConfiguration.class,
                        ResourceServerAutoConfiguration.class))
                .run(this::assertFailedNamingBothStarters);
    }

    @Test
    void givenOnlyResourceServerDeclaresMultiChain_thenStartupStillFailsNamingBothStarters() {
        baseRunner()
                .withPropertyValues("trust.security.resource-server.multi-chain.request-pattern=/api/**")
                .withConfiguration(AutoConfigurations.of(
                        ResourceServerAutoConfiguration.class,
                        OAuth2ClientAutoConfiguration.class))
                .run(this::assertFailedNamingBothStarters);
    }

    @Test
    void givenOnlyOAuth2ClientDeclaresMultiChain_thenStartupStillFailsNamingBothStarters() {
        baseRunner()
                .withPropertyValues("trust.security.oauth2-client.multi-chain.request-pattern=/**")
                .withConfiguration(AutoConfigurations.of(
                        ResourceServerAutoConfiguration.class,
                        OAuth2ClientAutoConfiguration.class))
                .run(this::assertFailedNamingBothStarters);
    }

    @Test
    void givenOverlappingMultiChainPatterns_thenStartupFailsWithOverlapException() {
        baseRunner()
                .withPropertyValues(
                        "trust.security.resource-server.multi-chain.request-pattern=/api/**",
                        "trust.security.oauth2-client.multi-chain.request-pattern=/api/admin/**")
                .withConfiguration(AutoConfigurations.of(
                        ResourceServerAutoConfiguration.class,
                        OAuth2ClientAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasFailed();
                    Throwable overlap = findMultiChainFailure(context.getStartupFailure());
                    assertThat(overlap).isNotNull();
                    assertThat(overlap.getMessage())
                            .contains("overlap")
                            .contains("/api/**")
                            .contains("/api/admin/**");
                });
    }

    @Test
    void givenDisjointMultiChainPatterns_thenBothStartersActivateTogether() {
        baseRunner()
                .withPropertyValues(
                        "trust.security.resource-server.multi-chain.request-pattern=/api/**",
                        "trust.security.oauth2-client.multi-chain.request-pattern=/app/**")
                .withConfiguration(AutoConfigurations.of(
                        ResourceServerAutoConfiguration.class,
                        OAuth2ClientAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasBean("jwtResourceServerFilterChain");
                    assertThat(context).hasBean("oauth2ClientFilterChain");
                });
    }

    /**
     * Exercises the exact mechanism {@code FilterChainProxy} uses to route a
     * real request to one chain or the other ({@code SecurityFilterChain.matches(request)},
     * verified by reading its source rather than assumed) - the strongest
     * available proof, short of a full HTTP round-trip, that the two chains
     * actually apply to disjoint request spaces and never both claim the
     * same request. Also documents, concretely, the one real caveat of this
     * feature: a path outside both declared patterns matches neither chain,
     * meaning it would reach the application with zero Spring Security
     * filtering at all (native {@code FilterChainProxy} behavior) - the two
     * patterns must together cover every path the application serves.
     */
    @Test
    void givenDisjointMultiChainPatterns_thenEachChainOnlyMatchesItsOwnRequestSpace() {
        baseRunner()
                .withPropertyValues(
                        "trust.security.resource-server.multi-chain.request-pattern=/api/**",
                        "trust.security.oauth2-client.multi-chain.request-pattern=/app/**")
                .withConfiguration(AutoConfigurations.of(
                        ResourceServerAutoConfiguration.class,
                        OAuth2ClientAutoConfiguration.class))
                .run(context -> {
                    SecurityFilterChain resourceServerChain =
                            context.getBean("jwtResourceServerFilterChain", SecurityFilterChain.class);
                    SecurityFilterChain oauth2ClientChain =
                            context.getBean("oauth2ClientFilterChain", SecurityFilterChain.class);

                    MockHttpServletRequest apiRequest = new MockHttpServletRequest("GET", "/api/documents");
                    assertThat(resourceServerChain.matches(apiRequest)).isTrue();
                    assertThat(oauth2ClientChain.matches(apiRequest)).isFalse();

                    MockHttpServletRequest appRequest = new MockHttpServletRequest("GET", "/app/dashboard");
                    assertThat(resourceServerChain.matches(appRequest)).isFalse();
                    assertThat(oauth2ClientChain.matches(appRequest)).isTrue();

                    // Documented behavior: a path outside both patterns matches
                    // neither chain - FilterChainProxy applies no security
                    // filtering to it.
                    MockHttpServletRequest uncoveredRequest = new MockHttpServletRequest("GET", "/other");
                    assertThat(resourceServerChain.matches(uncoveredRequest)).isFalse();
                    assertThat(oauth2ClientChain.matches(uncoveredRequest)).isFalse();
                });
    }

    private void assertFailedNamingBothStarters(AssertableWebApplicationContext context) {
        assertThat(context).hasFailed();

        Throwable startupFailure = context.getStartupFailure();
        assertThat(startupFailure).isNotNull();

        assertThat(findMultiChainFailure(startupFailure))
                .as("startup failure should be caused by one of the two multi-chain exceptions")
                .isNotNull();

        String message = rootCauseMessage(startupFailure);
        assertThat(message)
                .contains("trust-security-resource-server-starter")
                .contains("trust-security-oauth2-client-starter")
                .contains("multiple-SecurityFilterChain mode is not declared on both sides");
    }

    private static Throwable findMultiChainFailure(Throwable failure) {
        Throwable own = findCause(failure, MultiChainConfigurationException.class);
        return own != null
                ? own
                : findCause(failure, com.trust.security.client.multichain.MultiChainConfigurationException.class);
    }

    private static <T extends Throwable> T findCause(Throwable failure, Class<T> type) {
        while (failure != null) {
            if (type.isInstance(failure)) {
                return type.cast(failure);
            }
            failure = failure.getCause();
        }
        return null;
    }

    private static String rootCauseMessage(Throwable failure) {
        Throwable current = failure;
        while (current.getCause() != null && current.getCause() != current) {
            current = current.getCause();
        }
        return current.getMessage();
    }
}
