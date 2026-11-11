package com.trust.restclient.tokenrelay;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.web.ClientAttributes;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;

/**
 * Resolves which OAuth2 client registration a call should present a token
 * for, in order:
 * <ol>
 *     <li>the request attribute {@code @ClientRegistrationId} populates on
 *     the interface or method, if present - an explicit, per-call
 *     declaration always wins;</li>
 *     <li>otherwise, if the current authentication is an
 *     {@link OAuth2AuthenticationToken} (a BFF principal from
 *     {@code oauth2Login()}), the registration the user authenticated
 *     with - this <em>is</em> relaying the user, in BFF mode, without any
 *     configuration;</li>
 *     <li>otherwise, {@code null} - the native
 *     {@link OAuth2ClientHttpRequestInterceptor} abstains, exactly as it
 *     does when no attribute is present at all.</li>
 * </ol>
 *
 * <p>A resource-server principal ({@code JwtAuthenticationToken}) carries no
 * notion of "the registration it authenticated with" - only
 * {@link OAuth2AuthenticationToken} does - so step 3 is reached for that
 * case, and this resolver correctly abstains; {@link ResourceServerTokenRelayInterceptor}
 * from {@code com.trust.restclient}, not this resolver, is what relays a
 * resource server's incoming token.
 *
 * <p>Tested against all four combinations of {attribute present/absent} x
 * {BFF/resource-server authentication}.
 */
public final class TrustClientRegistrationIdResolver
        implements OAuth2ClientHttpRequestInterceptor.ClientRegistrationIdResolver {

    @Override
    public @Nullable String resolve(HttpRequest request) {
        String fromAttribute = ClientAttributes.resolveClientRegistrationId(request.getAttributes());
        if (fromAttribute != null) {
            return fromAttribute;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof OAuth2AuthenticationToken oauth2Authentication) {
            return oauth2Authentication.getAuthorizedClientRegistrationId();
        }

        return null;
    }
}
