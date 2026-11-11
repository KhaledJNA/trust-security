package com.trust.restclient.fixture.wire;

import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.web.service.annotation.GetExchange;

/**
 * A client-mode-only interface, isolated from {@link WireClient} in its own
 * group ({@link WireClientCredsPackageMarker}): declaring
 * {@code @ClientRegistrationId} makes the startup guard require an
 * {@code OAuth2AuthorizedClientManager} bean at startup, which most tests in
 * this suite do not configure and do not need.
 */
public interface WireClientCreds {

    @ClientRegistrationId("keycloak")
    @GetExchange("/ping")
    String pingAsClient();
}
