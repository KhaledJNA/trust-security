package com.trust.restclient.tokenrelay;

import io.github.resilience4j.retry.Retry;
import io.github.resilience4j.retry.RetryConfig;
import io.github.resilience4j.retry.RetryRegistry;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;

import java.io.IOException;
import java.time.Duration;

/**
 * Retries acquiring/refreshing an OAuth2 access token on a transient
 * failure talking to the identity provider - a connection-level
 * {@link IOException}, or an {@link OAuth2AuthorizationException} (the type
 * Spring Security normalizes IdP-side failures, network ones included,
 * into).
 *
 * <p>Deliberately independent from an HTTP service group's own retry and
 * circuit breaker: the identity provider being briefly slow is not a signal
 * about the downstream <em>API</em>'s health, and counting it as one would
 * misattribute an IdP blip as "this group is unhealthy" - wrong information
 * for whoever is looking at that group's circuit state.
 *
 * <p>One instance wraps the application's single {@code OAuth2AuthorizedClientManager}
 * regardless of how many registrations it serves - a
 * {@code @ClientRegistrationId} can name any registration, per call, so
 * this manager is shared rather than built once per registration. Its
 * {@link Retry} instances still live in the shared {@link RetryRegistry} (so
 * they get the same {@code resilience4j.retry.calls} metrics once a real
 * {@code MeterRegistry} exists), one per registration actually used -
 * resolved per call from {@link OAuth2AuthorizeRequest#getClientRegistrationId()},
 * not fixed at construction - so two different registrations never share
 * one token-acquisition health signal.
 */
public final class RetryingOAuth2AuthorizedClientManager implements OAuth2AuthorizedClientManager {

    private final OAuth2AuthorizedClientManager delegate;
    private final RetryRegistry retryRegistry;
    private final RetryConfig config;

    public RetryingOAuth2AuthorizedClientManager(
            OAuth2AuthorizedClientManager delegate, RetryRegistry retryRegistry,
            int maxAttempts, Duration waitDuration) {
        this.delegate = delegate;
        this.retryRegistry = retryRegistry;
        this.config = RetryConfig.custom()
                .maxAttempts(maxAttempts)
                .waitDuration(waitDuration)
                .retryOnException(RetryingOAuth2AuthorizedClientManager::isTransientAuthorizationFailure)
                .build();
    }

    @Override
    public OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest request) {
        Retry retry = retryRegistry.retry("oauth2:" + request.getClientRegistrationId(), config);
        return retry.executeSupplier(() -> delegate.authorize(request));
    }

    private static boolean isTransientAuthorizationFailure(Throwable throwable) {
        return throwable instanceof OAuth2AuthorizationException || throwable instanceof IOException;
    }
}
