package com.trust.restclient.fixture.wire;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.service.registry.HttpServiceGroup;
import org.springframework.web.service.registry.ImportHttpServices;

/**
 * Declares {@link WireClientTwoRegistrations} as its own native HTTP service
 * group ("wireClientTwoRegistrations") - see its Javadoc for why it is kept
 * separate from {@link WireClientCreds}.
 */
@Configuration
@ImportHttpServices(types = WireClientTwoRegistrations.class, group = "wireClientTwoRegistrations", clientType = HttpServiceGroup.ClientType.REST_CLIENT)
public class WireClientTwoRegistrationsPackageMarker {
}
