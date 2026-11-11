package com.trust.restclient.tokenrelay;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpRequest;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.ClientAttributes;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.client.web.client.SecurityContextHolderPrincipalResolver;
import org.springframework.security.oauth2.core.AuthorizationGrantType;

/**
 * Resolves the principal a {@code @ClientRegistrationId}-declared call is
 * authorized - and its token cached - under.
 * {@link org.springframework.security.oauth2.client.AuthorizedClientServiceOAuth2AuthorizedClientManager}
 * caches an {@code OAuth2AuthorizedClient} by the pair
 * {@code (registrationId, principal.getName())}, so this choice is also the
 * cache key.
 *
 * <ul>
 *     <li><b>Token-exchange registration</b>: the current user, from the
 *     security context - the exchanged token is issued for that user, so it
 *     must be cached per user (sharing it would hand user A's token to user
 *     B). With no authenticated user, throws {@link TokenExchangeSubjectException}
 *     before anything is sent: Spring's interceptor would otherwise substitute
 *     an anonymous principal, find nothing to exchange, and send the call
 *     with no {@code Authorization} header.</li>
 *     <li><b>Any other registration</b> ({@code client_credentials}): a
 *     stable technical principal, {@code "trust-client-credentials:" + registrationId},
 *     never the current user and never {@code null} - one application token
 *     shared by every caller, and usable with no request at all (batch,
 *     scheduled task, listener).</li>
 *     <li><b>No {@code @ClientRegistrationId}</b>: delegates to
 *     {@link SecurityContextHolderPrincipalResolver}, the resolver Spring
 *     Security installs by default - BFF relay is unaffected.</li>
 * </ul>
 */
public final class TrustPrincipalResolver implements OAuth2ClientHttpRequestInterceptor.PrincipalResolver {

    static final String PRINCIPAL_PREFIX = "trust-client-credentials:";

    private static final AuthenticationTrustResolver TRUST_RESOLVER = new AuthenticationTrustResolverImpl();

    private final OAuth2ClientHttpRequestInterceptor.PrincipalResolver delegate =
            new SecurityContextHolderPrincipalResolver();

    private final @Nullable ClientRegistrationRepository clientRegistrationRepository;

    public TrustPrincipalResolver(@Nullable ClientRegistrationRepository clientRegistrationRepository) {
        this.clientRegistrationRepository = clientRegistrationRepository;
    }

    @Override
    public @Nullable Authentication resolve(HttpRequest request) {
        String registrationId = ClientAttributes.resolveClientRegistrationId(request.getAttributes());
        if (registrationId == null) {
            return delegate.resolve(request);
        }

        if (isTokenExchange(registrationId)) {
            Authentication user = delegate.resolve(request);
            if (!TRUST_RESOLVER.isAuthenticated(user)) {
                throw new TokenExchangeSubjectException(
                        ("Call declared @ClientRegistrationId(\"%s\") uses token exchange, which needs an authenticated "
                                + "user whose token can be exchanged - but there is none in the current security "
                                + "context (batch, scheduled task, listener, or anonymous request). Use a "
                                + "client_credentials registration for calls made with no user.")
                                .formatted(registrationId));
            }
            return user;
        }

        String principalName = PRINCIPAL_PREFIX + registrationId;
        return new AnonymousAuthenticationToken(
                principalName, principalName, AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    }

    private boolean isTokenExchange(String registrationId) {
        if (clientRegistrationRepository == null) {
            return false;
        }
        ClientRegistration registration = clientRegistrationRepository.findByRegistrationId(registrationId);
        return registration != null
                && AuthorizationGrantType.TOKEN_EXCHANGE.equals(registration.getAuthorizationGrantType());
    }
}
