package com.trust.restclient.error;

import com.trust.web.problem.ProblemDetailsReader;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.json.ProblemDetailJacksonMixin;
import tools.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Behavioral tests for {@link ProblemDetailsResponseErrorHandler}: does it
 * correctly distinguish error from success, and does {@code handleError}
 * genuinely carry the parsed Problem Details through to the thrown
 * exception - not just report success at parsing without actually
 * propagating the result?
 *
 * <p>The {@code ObjectMapper} built here carries {@code ProblemDetailJacksonMixin}
 * explicitly, matching what Spring Boot's own {@code JacksonAutoConfiguration}
 * already registers on the real mapper {@code ServiceClientGroupConfigurer}
 * injects into {@link ProblemDetailsReader} in production -
 * {@code ProblemDetailsReader} itself does not register it a second time.
 */
class ProblemDetailsResponseErrorHandlerTest {

    private final ProblemDetailsResponseErrorHandler handler = new ProblemDetailsResponseErrorHandler(
            new ProblemDetailsReader(new ObjectMapper().rebuild()
                    .addMixIn(ProblemDetail.class, ProblemDetailJacksonMixin.class).build()));

    private static ClientHttpResponse responseWith(int statusCode, MediaType contentType, String body) throws Exception {
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        given(response.getStatusCode()).willReturn(HttpStatusCode.valueOf(statusCode));
        given(response.getStatusText()).willReturn(HttpStatusCode.valueOf(statusCode).toString());
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(contentType);
        given(response.getHeaders()).willReturn(headers);
        given(response.getBody()).willReturn(new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        return response;
    }

    @Test
    void given2xxResponse_whenCheckingForError_thenThereIsNone() throws Exception {
        ClientHttpResponse response = responseWith(200, MediaType.APPLICATION_JSON, "{}");

        assertThat(handler.hasError(response)).isFalse();
    }

    @Test
    void given4xxResponse_whenCheckingForError_thenThereIsOne() throws Exception {
        ClientHttpResponse response = responseWith(404, MediaType.APPLICATION_JSON, "{}");

        assertThat(handler.hasError(response)).isTrue();
    }

    @Test
    void given5xxResponse_whenCheckingForError_thenThereIsOne() throws Exception {
        ClientHttpResponse response = responseWith(503, MediaType.APPLICATION_JSON, "{}");

        assertThat(handler.hasError(response)).isTrue();
    }

    @Test
    void givenAProblemJsonErrorBody_whenHandlingTheError_thenTheThrownExceptionCarriesTheParsedProblemDetail()
            throws Exception {
        String body = "{\"status\":404,\"detail\":\"Order 42 not found\",\"correlationId\":\"corr-7\"}";
        ClientHttpResponse response = responseWith(404, MediaType.APPLICATION_PROBLEM_JSON, body);

        assertThatThrownBy(() -> handler.handleError(URI.create("http://api/orders/42"), HttpMethod.GET, response))
                .isInstanceOf(ServiceClientResponseException.class)
                .satisfies(e -> {
                    ServiceClientResponseException exception = (ServiceClientResponseException) e;
                    assertThat(exception.getStatusCode().value()).isEqualTo(404);
                    assertThat(exception.getProblemDetail()).isPresent();
                    assertThat(exception.getProblemDetail().get().getDetail()).isEqualTo("Order 42 not found");
                    assertThat(exception.getProblemDetail().get().getProperties())
                            .containsEntry("correlationId", "corr-7");
                    assertThat(exception.getMessage()).contains("Order 42 not found");
                });
    }

    @Test
    void givenANonProblemJsonErrorBody_whenHandlingTheError_thenTheExceptionStillCarriesTheRawBodyWithNoProblemDetail()
            throws Exception {
        ClientHttpResponse response = responseWith(500, MediaType.TEXT_PLAIN, "upstream is on fire");

        assertThatThrownBy(() -> handler.handleError(URI.create("http://api/orders/42"), HttpMethod.GET, response))
                .isInstanceOf(ServiceClientResponseException.class)
                .satisfies(e -> {
                    ServiceClientResponseException exception = (ServiceClientResponseException) e;
                    assertThat(exception.getProblemDetail()).isEmpty();
                    assertThat(exception.getResponseBodyAsString()).isEqualTo("upstream is on fire");
                    assertThat(exception.getMessage()).contains("upstream is on fire");
                });
    }

    @Test
    void givenAnEmptyErrorBody_whenHandlingTheError_thenTheMessageSaysSoExplicitly() throws Exception {
        ClientHttpResponse response = responseWith(503, MediaType.TEXT_PLAIN, "");

        assertThatThrownBy(() -> handler.handleError(URI.create("http://api/orders/42"), HttpMethod.GET, response))
                .isInstanceOf(ServiceClientResponseException.class)
                .hasMessageContaining("[no body]");
    }
}
