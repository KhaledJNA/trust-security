package com.trust.restclient.observation;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequest;
import org.springframework.http.client.observation.ClientRequestObservationContext;

import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Behavioral tests for {@link ServiceClientRequestObservationConvention}:
 * does it genuinely replace the {@code client.name} tag with the Trust
 * client name, while leaving the rest of Spring's default tagging (method,
 * URI) untouched?
 */
class ServiceClientRequestObservationConventionTest {

    private static ClientRequestObservationContext contextFor(HttpMethod method, URI uri) {
        ClientHttpRequest request = mock(ClientHttpRequest.class);
        given(request.getMethod()).willReturn(method);
        given(request.getURI()).willReturn(uri);
        given(request.getHeaders()).willReturn(new HttpHeaders());
        return new ClientRequestObservationContext(request);
    }

    @Test
    void givenAConventionForAClientName_whenComputingTags_thenTheClientNameTagUsesIt() {
        ServiceClientRequestObservationConvention convention =
                new ServiceClientRequestObservationConvention("documentsClient");
        ClientRequestObservationContext context = contextFor(HttpMethod.GET, URI.create("http://internal-host/documents"));

        String clientName = convention.getLowCardinalityKeyValues(context).stream()
                .filter(keyValue -> keyValue.getKey().equals("client.name"))
                .findFirst()
                .orElseThrow()
                .getValue();

        assertThat(clientName).isEqualTo("documentsClient");
    }

    @Test
    void givenTwoDifferentClientsOnTheSameHost_whenComputingTags_thenEachKeepsItsOwnDistinctClientNameTag() {
        URI sameHost = URI.create("http://shared-host/a");

        String first = new ServiceClientRequestObservationConvention("clientA")
                .getLowCardinalityKeyValues(contextFor(HttpMethod.GET, sameHost)).stream()
                .filter(keyValue -> keyValue.getKey().equals("client.name"))
                .findFirst().orElseThrow().getValue();
        String second = new ServiceClientRequestObservationConvention("clientB")
                .getLowCardinalityKeyValues(contextFor(HttpMethod.GET, sameHost)).stream()
                .filter(keyValue -> keyValue.getKey().equals("client.name"))
                .findFirst().orElseThrow().getValue();

        assertThat(first).isEqualTo("clientA");
        assertThat(second).isEqualTo("clientB");
    }

    @Test
    void givenAMethodAndUri_whenComputingTags_thenTheyStillReflectTheRealRequestAsSpringDefaultDoes() {
        ServiceClientRequestObservationConvention convention =
                new ServiceClientRequestObservationConvention("documentsClient");
        ClientRequestObservationContext context = contextFor(HttpMethod.PUT, URI.create("http://internal-host/documents/42"));

        String method = convention.getLowCardinalityKeyValues(context).stream()
                .filter(keyValue -> keyValue.getKey().equals("method"))
                .findFirst().orElseThrow().getValue();

        assertThat(method).isEqualTo("PUT");
    }
}
