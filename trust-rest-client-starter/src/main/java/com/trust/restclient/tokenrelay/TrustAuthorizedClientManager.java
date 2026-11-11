package com.trust.restclient.tokenrelay;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.TokenExchangeOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2Token;

import java.util.Set;

/**
 * Trust's default {@link OAuth2AuthorizedClientManager}, supporting exactly
 * two grant types - {@link #SUPPORTED_GRANT_TYPES}:
 * <ul>
 *     <li>{@code client_credentials} - a token for the application itself;</li>
 *     <li>{@code token-exchange} (RFC 8693) - the current user's incoming
 *     token is exchanged for a new one, still issued for that user, but
 *     scoped to the target (audience, scopes) - see {@link #resolveSubjectToken}.</li>
 * </ul>
 * A distinct, marked type wrapping {@link AuthorizedClientServiceOAuth2AuthorizedClientManager}
 * (which is {@code final}, hence composition rather than inheritance, the
 * same shape already used by {@link RetryingOAuth2AuthorizedClientManager}).
 * Its type lets {@code ServiceClientGroupConfigurer} recognize that the
 * active manager is this one - whose supported grant types are known
 * exactly - and never an application-supplied manager, whose supported
 * grant types Trust has no way of knowing.
 *
 * <p>That distinction matters for one guard: a {@code @ClientRegistrationId}
 * naming a registration of any other grant type must fail at startup, not
 * at request time - an unsupported grant type makes Spring's providers
 * return {@code null}, and the call would go out with no
 * {@code Authorization} header at all.
 */
public final class TrustAuthorizedClientManager implements OAuth2AuthorizedClientManager {

    public static final Set<AuthorizationGrantType> SUPPORTED_GRANT_TYPES =
            Set.of(AuthorizationGrantType.CLIENT_CREDENTIALS, AuthorizationGrantType.TOKEN_EXCHANGE);

    private final OAuth2AuthorizedClientManager delegate;

    public TrustAuthorizedClientManager(
            ClientRegistrationRepository clientRegistrationRepository,
            OAuth2AuthorizedClientService authorizedClientService) {

        AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
                new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                        clientRegistrationRepository, authorizedClientService);

        TokenExchangeOAuth2AuthorizedClientProvider tokenExchange = new TokenExchangeOAuth2AuthorizedClientProvider();
        tokenExchange.setSubjectTokenResolver(TrustAuthorizedClientManager::resolveSubjectToken);

        OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder()
                .clientCredentials()
                .provider(tokenExchange)
                .build();
        manager.setAuthorizedClientProvider(provider);

        this.delegate = manager;
    }

    @Override
    public @Nullable OAuth2AuthorizedClient authorize(OAuth2AuthorizeRequest authorizeRequest) {
        return delegate.authorize(authorizeRequest);
    }

    /**
     * The incoming user's token, presented as the {@code subject_token} of
     * the exchange. Replaces Spring's default resolver for two reasons:
     * <ul>
     *     <li>Spring's default only finds a JWT ({@code Authentication#getPrincipal()}
     *     is a {@code Jwt}); for an opaque token ({@code BearerTokenAuthentication})
     *     the principal is an {@code OAuth2AuthenticatedPrincipal}, so it
     *     finds nothing - and the call then goes out with no
     *     {@code Authorization} header. Both resource-server authentication
     *     types expose their token as {@link Authentication#getCredentials()},
     *     which is read here without depending on the (optional)
     *     resource-server module.</li>
     *     <li>Spring sends a {@code Jwt} with {@code subject_token_type=...:jwt};
     *     Keycloak's standard token exchange only accepts
     *     {@code ...:access_token}. The incoming token <em>is</em> an access
     *     token, so it is always presented as one.</li>
     * </ul>
     * Never returns {@code null}: an authenticated user without a token
     * (form login, a BFF session principal) cannot be exchanged, and that
     * fails the call instead of letting it go out unauthenticated.
     */
    static OAuth2Token resolveSubjectToken(OAuth2AuthorizationContext context) {
        Authentication principal = context.getPrincipal();
        OAuth2Token token = principal.getCredentials() instanceof OAuth2Token credentials ? credentials : null;
        if (token == null) {
            throw new TokenExchangeSubjectException(
                    ("Token exchange for registration '%s' needs the current user's incoming bearer token, but the "
                            + "current authentication (%s) carries none. Token exchange is only available while "
                            + "handling a request authenticated by a JWT or an opaque token (resource-server mode).")
                            .formatted(context.getClientRegistration().getRegistrationId(),
                                    principal.getClass().getSimpleName()));
        }
        if (token instanceof OAuth2AccessToken accessToken) {
            return accessToken;
        }
        return new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                token.getTokenValue(), token.getIssuedAt(), token.getExpiresAt());
    }
}
