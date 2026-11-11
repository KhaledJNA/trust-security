package com.trust.restclient.fixture.wire;

import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.web.service.annotation.GetExchange;

/**
 * Two distinct {@code @ClientRegistrationId} methods on the same interface -
 * kept entirely separate from {@link WireClientCreds} (isolated in its own
 * group, {@link WireClientTwoRegistrationsPackageMarker}) so that this
 * fixture's need for two real registrations to be configured at once never
 * forces every other test using {@code WireClientCreds} to also configure a
 * second, unrelated registration just to satisfy the startup guard. Used
 * only by the wire test proving two {@code client_credentials} registrations
 * never share a cached token - each method targets a different endpoint
 * ({@code /ping} vs. {@code /create}) so their traffic can be told apart on
 * the wire.
 */
public interface WireClientTwoRegistrations {

    @ClientRegistrationId("keycloak")
    @GetExchange("/ping")
    String pingAsClient();

    @ClientRegistrationId("other-m2m")
    @GetExchange("/create")
    String createAsClient();
}
