package com.trust.restclient.tokenrelay;

import io.github.resilience4j.retry.RetryRegistry;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioral tests for {@link RetryingOAuth2AuthorizedClientManager}: does
 * it genuinely retry a transient identity-provider failure, and correctly
 * leave a non-transient one alone?
 */
class RetryingOAuth2AuthorizedClientManagerTest {

    private static final Duration NO_DELAY = Duration.ofMillis(1);

    private static OAuth2AuthorizeRequest anyRequest() {
        return OAuth2AuthorizeRequest.withClientRegistrationId("keycloak")
                .principal("trust.user")
                .build();
    }

    private static OAuth2AuthorizedClient anyAuthorizedClient() {
        ClientRegistration registration = ClientRegistration.withRegistrationId("keycloak")
                .clientId("bff")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .tokenUri("https://idp.example.com/token")
                .build();
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, "token-value", Instant.EPOCH, Instant.EPOCH.plusSeconds(3600));
        return new OAuth2AuthorizedClient(registration, "trust.user", accessToken);
    }

    private static ClientAuthorizationException idpFailure() {
        return new ClientAuthorizationException(
                new OAuth2Error("server_error", "the identity provider is temporarily unavailable", null),
                "keycloak");
    }

    /** A fake rather than a Mockito mock, for the same reason as the retry/circuit-breaker interceptor tests: a scripted sequence of distinct outcomes. */
    private static final class ScriptedManager implements OAuth2AuthorizedClientManager {

        private final Deque<Object> outcomes;
        private int callCount = 0;

        ScriptedManager(Object... outcomes) {
            this.outcomes = new ArrayDeque<>(java.util.List.of(outcomes));
        }

        @Override
        public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest request) {
            callCount++;
            Object outcome = outcomes.poll();
            if (outcome instanceof RuntimeException runtimeException) {
                throw runtimeException;
            }
            return (OAuth2AuthorizedClient) outcome;
        }
    }

    @Test
    void givenATransientFailureThenSuccess_whenAuthorizing_thenItRetriesOnceAndReturnsTheToken() {
        OAuth2AuthorizedClient success = anyAuthorizedClient();
        ScriptedManager delegate = new ScriptedManager(idpFailure(), success);
        RetryingOAuth2AuthorizedClientManager manager = new RetryingOAuth2AuthorizedClientManager(
                delegate, RetryRegistry.ofDefaults(), 3, NO_DELAY);

        OAuth2AuthorizedClient result = manager.authorize(anyRequest());

        assertThat(result).isSameAs(success);
        assertThat(delegate.callCount).isEqualTo(2);
    }

    @Test
    void givenPersistentTransientFailures_whenAuthorizing_thenItStopsAfterMaxAttemptsAndRethrows() {
        ClientAuthorizationException failure = idpFailure();
        ScriptedManager delegate = new ScriptedManager(failure, failure, failure);
        RetryingOAuth2AuthorizedClientManager manager = new RetryingOAuth2AuthorizedClientManager(
                delegate, RetryRegistry.ofDefaults(), 3, NO_DELAY);

        assertThatThrownBy(() -> manager.authorize(anyRequest())).isSameAs(failure);
        assertThat(delegate.callCount).isEqualTo(3);
    }

    @Test
    void givenANonTransientFailure_whenAuthorizing_thenItIsNotRetried() {
        IllegalStateException notAuthorizationRelated = new IllegalStateException("programming error");
        ScriptedManager delegate = new ScriptedManager(notAuthorizationRelated);
        RetryingOAuth2AuthorizedClientManager manager = new RetryingOAuth2AuthorizedClientManager(
                delegate, RetryRegistry.ofDefaults(), 3, NO_DELAY);

        assertThatThrownBy(() -> manager.authorize(anyRequest())).isSameAs(notAuthorizationRelated);
        assertThat(delegate.callCount).isEqualTo(1);
    }

    @Test
    void givenTwoDifferentRegistrations_whenOneFailsPersistently_thenTheOthersRetryBudgetIsUnaffected() {
        ClientAuthorizationException failure = idpFailure();
        OAuth2AuthorizedClient success = anyAuthorizedClient();
        // "broken" exhausts its retry budget every time; "healthy" always succeeds immediately.
        ScriptedManager delegate = new ScriptedManager(failure, failure, failure, success);
        RetryingOAuth2AuthorizedClientManager manager = new RetryingOAuth2AuthorizedClientManager(
                delegate, RetryRegistry.ofDefaults(), 3, NO_DELAY);

        OAuth2AuthorizeRequest broken = OAuth2AuthorizeRequest.withClientRegistrationId("broken")
                .principal("trust.user").build();
        OAuth2AuthorizeRequest healthy = OAuth2AuthorizeRequest.withClientRegistrationId("healthy")
                .principal("trust.user").build();

        assertThatThrownBy(() -> manager.authorize(broken)).isSameAs(failure);
        assertThat(delegate.callCount).isEqualTo(3);

        OAuth2AuthorizedClient result = manager.authorize(healthy);
        assertThat(result).isSameAs(success);
        assertThat(delegate.callCount).isEqualTo(4);
    }

    @Test
    void givenImmediateSuccess_whenAuthorizing_thenItIsCalledExactlyOnce() {
        OAuth2AuthorizedClient success = anyAuthorizedClient();
        ScriptedManager delegate = new ScriptedManager(success);
        RetryingOAuth2AuthorizedClientManager manager = new RetryingOAuth2AuthorizedClientManager(
                delegate, RetryRegistry.ofDefaults(), 3, NO_DELAY);

        assertThat(manager.authorize(anyRequest())).isSameAs(success);
        assertThat(delegate.callCount).isEqualTo(1);
    }
}
