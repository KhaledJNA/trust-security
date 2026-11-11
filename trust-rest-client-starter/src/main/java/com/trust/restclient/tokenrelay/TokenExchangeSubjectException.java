package com.trust.restclient.tokenrelay;

/**
 * Thrown when a call declared {@code @ClientRegistrationId} on a
 * {@code token-exchange} registration is made without a user token to
 * exchange - no authenticated user at all (batch, scheduled task, listener,
 * anonymous request), or a user authenticated without a bearer token.
 *
 * <p>Thrown before the target API is reached: a call declared as made on a
 * user's behalf never goes out unauthenticated, and never falls back to the
 * application's own identity.
 *
 * <p>Deliberately not an {@code OAuth2AuthorizationException}: this is a
 * programming/context error, not an identity-provider failure, so
 * {@link RetryingOAuth2AuthorizedClientManager} must not retry it.
 */
public class TokenExchangeSubjectException extends IllegalStateException {

    public TokenExchangeSubjectException(String message) {
        super(message);
    }
}
