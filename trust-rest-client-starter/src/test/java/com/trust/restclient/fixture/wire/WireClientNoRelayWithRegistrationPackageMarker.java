package com.trust.restclient.fixture.wire;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.service.registry.HttpServiceGroup;
import org.springframework.web.service.registry.ImportHttpServices;

/** Declares {@link WireClientNoRelayWithRegistration} as its own group ("wireClientNoRelay"). */
@Configuration
@ImportHttpServices(types = WireClientNoRelayWithRegistration.class, group = "wireClientNoRelay",
        clientType = HttpServiceGroup.ClientType.REST_CLIENT)
public class WireClientNoRelayWithRegistrationPackageMarker {
}
