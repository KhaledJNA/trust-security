package com.trust.restclient.observation;

import io.micrometer.common.KeyValue;
import org.springframework.http.client.observation.ClientHttpObservationDocumentation.LowCardinalityKeyNames;
import org.springframework.http.client.observation.ClientRequestObservationContext;
import org.springframework.http.client.observation.DefaultClientRequestObservationConvention;

/**
 * Tags every {@code http.client.requests} observation for an HTTP service
 * group with the group's name - the same identifier already used to name
 * its retry and circuit breaker instances - instead of Spring's own default,
 * the request's URI host.
 *
 * <p>The host is often good enough (different downstream services usually
 * live on different hosts), but it isn't always stable or unique: two
 * groups can share a host on different paths, and a group's URL can change
 * across environments while its name stays the same. Tagging by group name
 * keeps dashboards and alerts tied to a stable identifier that also already
 * appears in retry/circuit-breaker metrics for the same group.
 */
public final class ServiceClientRequestObservationConvention extends DefaultClientRequestObservationConvention {

    private final KeyValue clientName;

    public ServiceClientRequestObservationConvention(String clientName) {
        this.clientName = KeyValue.of(LowCardinalityKeyNames.CLIENT_NAME, clientName);
    }

    @Override
    protected KeyValue clientName(ClientRequestObservationContext context) {
        return clientName;
    }
}
