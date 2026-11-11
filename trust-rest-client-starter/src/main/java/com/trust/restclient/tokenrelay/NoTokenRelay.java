package com.trust.restclient.tokenrelay;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Forbids {@link com.trust.restclient.ResourceServerTokenRelayInterceptor}
 * from relaying the current user's bearer token (JWT or opaque) on a call -
 * answers the "which cases must relay be forbidden for" question left open
 * for token relay: some downstream calls (e.g. a public, unauthenticated
 * endpoint reached through the same declarative client; a call whose target
 * must never see the calling user's identity) must never carry it, even
 * though nothing else about the call looks different from ones that should.
 *
 * <p>May be placed on an interface (forbids relay for every method of that
 * client - "by client") or on a single method (forbids it just for that
 * call) - unlike {@code @NoRetry}, which is method-only, since the need
 * expressed for this annotation is explicitly per-client as well as
 * per-method.
 *
 * <p>Scoped to {@link com.trust.restclient.ResourceServerTokenRelayInterceptor}
 * only: it has no effect on the BFF/{@code @ClientRegistrationId} relay path
 * ({@code TrustClientRegistrationIdResolver}/native {@code OAuth2ClientHttpRequestInterceptor}),
 * which declares its own token.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.TYPE, ElementType.METHOD})
public @interface NoTokenRelay {
}
