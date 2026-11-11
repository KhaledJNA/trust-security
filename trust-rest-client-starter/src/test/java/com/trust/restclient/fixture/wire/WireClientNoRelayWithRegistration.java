package com.trust.restclient.fixture.wire;

import com.trust.restclient.tokenrelay.NoTokenRelay;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.web.service.annotation.GetExchange;

/**
 * {@code @ClientRegistrationId} on the interface, {@code @NoTokenRelay} on
 * one method - contradictory when the registration is a token-exchange one
 * (the exchanged token still identifies the user), harmless when it is
 * {@code client_credentials}.
 */
@ClientRegistrationId("keycloak")
public interface WireClientNoRelayWithRegistration {

    @NoTokenRelay
    @GetExchange("/ping")
    String ping();
}
