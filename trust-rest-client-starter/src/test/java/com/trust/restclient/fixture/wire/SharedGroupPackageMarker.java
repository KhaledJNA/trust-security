package com.trust.restclient.fixture.wire;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.service.registry.HttpServiceGroup;
import org.springframework.web.service.registry.ImportHttpServices;

/** Deliberately declares two interfaces in one group, for the multi-interface startup warning test. */
@Configuration
@ImportHttpServices(
        types = {SharedGroupClientA.class, SharedGroupClientB.class},
        group = "sharedGroup",
        clientType = HttpServiceGroup.ClientType.REST_CLIENT)
public class SharedGroupPackageMarker {
}
