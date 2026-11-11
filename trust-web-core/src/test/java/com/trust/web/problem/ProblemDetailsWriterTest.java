package com.trust.web.problem;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioral tests for {@link ProblemDetailsWriter}, based on the actual, observed
 * behavior of {@link org.springframework.http.ProblemDetail}:
 * - the title is populated only when the status code resolves to a known {@link org.springframework.http.HttpStatus}
 * - the writer never sets the HTTP status itself: it only reflects whatever status is
 *   already present on the response (the caller is responsible for setting it beforehand)
 */
class ProblemDetailsWriterTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ProblemDetailsWriter writer = new ProblemDetailsWriter(objectMapper);

    @Test
    void constructor_rejectsNullObjectMapper() {
        assertThatThrownBy(() -> new ProblemDetailsWriter(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void givenStandardHttpStatus_whenWritingProblemDetails_thenResponseCarriesProblemJsonWithStatusTitleDetailAndInstance() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders/42");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(404);

        writer.write(request, response, "Order 42 not found");

        assertThat(response.getContentType()).isEqualTo("application/problem+json;charset=UTF-8");
        assertThat(response.getCharacterEncoding()).isEqualTo("UTF-8");

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(404);
        assertThat(body.get("title").asString()).isEqualTo("Not Found");
        assertThat(body.get("detail").asString()).isEqualTo("Order 42 not found");
        assertThat(body.get("instance").asString()).isEqualTo("/orders/42");
    }

    @Test
    void givenNonStandardStatusCode_whenWritingProblemDetails_thenTitleIsNotPopulated() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/custom");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(599);

        writer.write(request, response, "custom failure");

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(599);
        assertThat(body.hasNonNull("title")).isFalse();
        assertThat(body.get("detail").asString()).isEqualTo("custom failure");
    }

    @Test
    void givenNoStatusExplicitlySetOnResponse_whenWritingProblemDetails_thenResponseDefaultStatusOfTwoHundredIsReflected() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();

        writer.write(request, response, "detail without explicit status");

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(200);
    }

    @Test
    void givenNullDetail_whenWritingProblemDetails_thenBodyIsWrittenWithoutDetailField() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.setStatus(400);

        writer.write(request, response, null);

        JsonNode body = objectMapper.readTree(response.getContentAsByteArray());
        assertThat(body.get("status").asInt()).isEqualTo(400);
        assertThat(body.get("title").asString()).isEqualTo("Bad Request");
        assertThat(body.hasNonNull("detail")).isFalse();
    }

    @Test
    void givenResponseAlreadyCommitted_whenWritingProblemDetails_thenNothingIsWritten() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/orders");
        MockHttpServletResponse response = new MockHttpServletResponse();
        response.getOutputStream().write("already sent".getBytes());
        response.flushBuffer();

        writer.write(request, response, "should not appear");

        assertThat(response.getContentAsString()).isEqualTo("already sent");
        assertThat(response.getContentType()).isNull();
    }
}
