package com.trust.restclient;

import com.trust.restclient.tokenrelay.NoTokenRelayProcessor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.web.ClientAttributes;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.IOException;

/**
 * Relays the incoming bearer token on outgoing calls made from a resource server.
 *
 * <p>Resource servers are stateless: the token is carried by the current
 * {@link JwtAuthenticationToken} (JWT) or {@link BearerTokenAuthentication}
 * (opaque token, validated by RFC 7662 introspection) rather than stored in
 * an HTTP session. It is therefore read directly from the security context,
 * with no authorized client manager involved.
 *
 * <p>The token cannot be refreshed here — resource servers hold no refresh
 * token. Call chains should stay short enough for the original token to remain
 * valid, or use token exchange (RFC 8693) beyond a couple of hops.
 *
 * <p><b>Abstains whenever the call is targeted at a declared registration</b>
 * (an interface or method annotated {@code @ClientRegistrationId}), by
 * reading the same request attribute
 * {@link org.springframework.security.oauth2.client.annotation.ClientRegistrationId}
 * populates - the public method
 * {@link ClientAttributes#resolveClientRegistrationId(java.util.Map)}, the
 * same one the native {@code OAuth2ClientHttpRequestInterceptor} reads
 * internally. This does not depend on running before or after that native
 * interceptor in the chain: this interceptor never sets a header for a call
 * it does not own, regardless of whether the native one later succeeds,
 * fails, or is even present. Relying on this interceptor's header being merely
 * <em>overwritten</em> by the native one - rather than never set in the
 * first place - lets the incoming user's token leak to a call meant to
 * carry an application token, the moment the native interceptor fails to
 * obtain one (a misconfigured grant, a manager returning {@code null}).
 *
 * <p><b>Also abstains whenever the call (or its declaring interface) is
 * annotated {@code @NoTokenRelay}</b> ({@link com.trust.restclient.tokenrelay.NoTokenRelay}),
 * read via {@link NoTokenRelayProcessor#isSuppressed(HttpRequest)} - the same
 * request-attribute channel {@code @NoRetry} uses for retry suppression.
 * Applies uniformly to both token origins above: a call declared
 * {@code @NoTokenRelay} never carries a bearer, whether the incoming
 * authentication is a JWT or an opaque token.
 */
public class ResourceServerTokenRelayInterceptor implements ClientHttpRequestInterceptor {

    private static final Logger log = LoggerFactory.getLogger(ResourceServerTokenRelayInterceptor.class);

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body,
                                        ClientHttpRequestExecution execution) throws IOException {

        String targetedRegistration = ClientAttributes.resolveClientRegistrationId(request.getAttributes());
        if (targetedRegistration != null) {
            if (log.isDebugEnabled()) {
                log.debug("Call targeted at registration '{}' via @ClientRegistrationId - "
                        + "not this interceptor's call, abstaining.", targetedRegistration);
            }
            return execution.execute(request, body);
        }

        if (NoTokenRelayProcessor.isSuppressed(request)) {
            if (log.isDebugEnabled()) {
                log.debug("Call annotated @NoTokenRelay - relay forbidden for this client/method, abstaining.");
            }
            return execution.execute(request, body);
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            request.getHeaders().setBearerAuth(jwtAuthentication.getToken().getTokenValue());
        } else if (authentication instanceof BearerTokenAuthentication bearerAuthentication) {
            request.getHeaders().setBearerAuth(bearerAuthentication.getToken().getTokenValue());
        }

        return execution.execute(request, body);
    }
}
