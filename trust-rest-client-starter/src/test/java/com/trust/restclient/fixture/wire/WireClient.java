package com.trust.restclient.fixture.wire;

import com.trust.restclient.retry.NoRetry;
import com.trust.restclient.tokenrelay.NoTokenRelay;
import org.springframework.web.service.annotation.GetExchange;
import org.springframework.web.service.annotation.PostExchange;

/**
 * The single client interface exercised by the wire-behavior characterization
 * suite - declared natively ({@code @HttpExchange} family, imported by
 * {@link WirePackageMarker} via {@code @ImportHttpServices}), deliberately
 * generic: the point of that suite is to observe what crosses the wire, not
 * to exercise any one business shape. Carries no {@code @ClientRegistrationId}
 * method - see {@link WireClientCreds} for that, isolated in its own group so
 * that the startup guard (fails startup when a declared registration has no
 * {@code OAuth2AuthorizedClientManager}) does not affect every other test
 * sharing this fixture.
 */
public interface WireClient {

    @GetExchange("/ping")
    String ping();

    @PostExchange("/create")
    String create();

    @NoRetry
    @GetExchange("/ping")
    String noRetryPing();

    @NoTokenRelay
    @GetExchange("/ping")
    String noTokenRelayPing();

    @GetExchange("/slow")
    String slow();

    @GetExchange("/fail")
    String fail();
}
