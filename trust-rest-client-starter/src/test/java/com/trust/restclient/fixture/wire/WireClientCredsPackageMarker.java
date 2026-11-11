package com.trust.restclient.fixture.wire;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.service.registry.HttpServiceGroup;
import org.springframework.web.service.registry.ImportHttpServices;

/**
 * Declares {@link WireClientCreds} as its own native HTTP service group
 * ("wireClientCreds") - see {@link WireClientCreds}'s Javadoc for why it is
 * kept separate from {@link WireClient}'s group.
 */
@Configuration
@ImportHttpServices(types = WireClientCreds.class, group = "wireClientCreds", clientType = HttpServiceGroup.ClientType.REST_CLIENT)
public class WireClientCredsPackageMarker {
}
