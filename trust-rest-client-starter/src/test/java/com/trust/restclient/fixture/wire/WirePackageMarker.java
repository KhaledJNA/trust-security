package com.trust.restclient.fixture.wire;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.service.registry.HttpServiceGroup;
import org.springframework.web.service.registry.ImportHttpServices;

/**
 * Declares {@link WireClient} as its own native HTTP service group
 * ("wireClient") for the characterization suite
 * ({@code ServiceClientWireCharacterizationTest}) - the same declaration
 * shape an application uses, exercised here as a fixture.
 */
@Configuration
@ImportHttpServices(types = WireClient.class, group = "wireClient", clientType = HttpServiceGroup.ClientType.REST_CLIENT)
public class WirePackageMarker {
}
