package com.trust.web.problem;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.json.ProblemDetailJacksonMixin;
import tools.jackson.databind.ObjectMapper;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioral tests for {@link ProblemDetailsReader} - the exact symmetric
 * counterpart of {@link ProblemDetailsWriterTest}: what one side writes,
 * the other must read back faithfully, extension members included.
 *
 * <p>The {@code ObjectMapper} built here carries {@code ProblemDetailJacksonMixin}
 * explicitly, matching what Spring Boot's own {@code JacksonAutoConfiguration}
 * already registers on any auto-configured mapper in a real application -
 * {@link ProblemDetailsReader} itself does not register it a second time.
 */
class ProblemDetailsReaderTest {

    private final ProblemDetailsReader reader = new ProblemDetailsReader(
            new ObjectMapper().rebuild().addMixIn(ProblemDetail.class, ProblemDetailJacksonMixin.class).build());

    @Test
    void constructor_rejectsNullObjectMapper() {
        assertThatThrownBy(() -> new ProblemDetailsReader(null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void givenARealProblemJsonBody_whenReading_thenTheStandardMembersAreAllPopulated() {
        byte[] body = ("{\"type\":\"https://example.com/probs/not-found\",\"title\":\"Not Found\","
                + "\"status\":404,\"detail\":\"Order 42 not found\",\"instance\":\"/orders/42\"}")
                .getBytes(StandardCharsets.UTF_8);

        Optional<ProblemDetail> problemDetail = reader.read(MediaType.APPLICATION_PROBLEM_JSON, body);

        assertThat(problemDetail).isPresent();
        assertThat(problemDetail.get().getType()).isEqualTo(URI.create("https://example.com/probs/not-found"));
        assertThat(problemDetail.get().getTitle()).isEqualTo("Not Found");
        assertThat(problemDetail.get().getStatus()).isEqualTo(404);
        assertThat(problemDetail.get().getDetail()).isEqualTo("Order 42 not found");
        assertThat(problemDetail.get().getInstance()).isEqualTo(URI.create("/orders/42"));
    }

    /**
     * Depends entirely on the mixin the injected {@code ObjectMapper} already
     * carries (Spring Boot's own {@code JacksonAutoConfiguration} does this
     * in a real application): without it, this extension member would
     * silently disappear instead of failing - verified empirically.
     */
    @Test
    void givenAProblemJsonBodyWithAnExtensionMember_whenReading_thenItIsPreservedNotSilentlyDropped() {
        byte[] body = ("{\"status\":400,\"detail\":\"invalid input\",\"correlationId\":\"corr-42\"}")
                .getBytes(StandardCharsets.UTF_8);

        Optional<ProblemDetail> problemDetail = reader.read(MediaType.APPLICATION_PROBLEM_JSON, body);

        assertThat(problemDetail).isPresent();
        assertThat(problemDetail.get().getProperties()).containsEntry("correlationId", "corr-42");
    }

    /**
     * Documents the precondition this class now relies on rather than
     * enforces itself: a caller-supplied {@code ObjectMapper} with no
     * {@code ProblemDetailJacksonMixin} still parses successfully, but
     * drops extension members without any error - Spring Boot's
     * {@code JacksonAutoConfiguration} is what must supply that mixin in a
     * real application.
     */
    @Test
    void givenAnObjectMapperWithoutTheMixin_whenReadingAnExtensionMember_thenItIsSilentlyDropped() {
        ProblemDetailsReader readerWithoutMixin = new ProblemDetailsReader(new ObjectMapper());
        byte[] body = ("{\"status\":400,\"detail\":\"invalid input\",\"correlationId\":\"corr-42\"}")
                .getBytes(StandardCharsets.UTF_8);

        Optional<ProblemDetail> problemDetail = readerWithoutMixin.read(MediaType.APPLICATION_PROBLEM_JSON, body);

        assertThat(problemDetail).isPresent();
        assertThat(problemDetail.get().getProperties()).isNullOrEmpty();
    }

    @Test
    void givenANonProblemJsonContentType_whenReading_thenNothingIsParsed() {
        byte[] body = "{\"status\":400,\"detail\":\"invalid input\"}".getBytes(StandardCharsets.UTF_8);

        Optional<ProblemDetail> problemDetail = reader.read(MediaType.APPLICATION_JSON, body);

        assertThat(problemDetail).isEmpty();
    }

    @Test
    void givenNoContentType_whenReading_thenNothingIsParsed() {
        byte[] body = "{\"status\":400,\"detail\":\"invalid input\"}".getBytes(StandardCharsets.UTF_8);

        Optional<ProblemDetail> problemDetail = reader.read(null, body);

        assertThat(problemDetail).isEmpty();
    }

    @Test
    void givenAnEmptyBody_whenReading_thenNothingIsParsed() {
        Optional<ProblemDetail> problemDetail = reader.read(MediaType.APPLICATION_PROBLEM_JSON, new byte[0]);

        assertThat(problemDetail).isEmpty();
    }

    @Test
    void givenAProblemJsonContentTypeButABodyThatIsNotValidJson_whenReading_thenNothingIsParsed() {
        byte[] body = "not json at all".getBytes(StandardCharsets.UTF_8);

        Optional<ProblemDetail> problemDetail = reader.read(MediaType.APPLICATION_PROBLEM_JSON, body);

        assertThat(problemDetail).isEmpty();
    }

    @Test
    void givenAJsonNullBody_whenReading_thenNothingIsParsed() {
        byte[] body = "null".getBytes(StandardCharsets.UTF_8);

        Optional<ProblemDetail> problemDetail = reader.read(MediaType.APPLICATION_PROBLEM_JSON, body);

        assertThat(problemDetail).isEmpty();
    }

    @Test
    void givenAContentTypeWithCharsetParameter_whenReading_thenItIsStillRecognizedAsProblemJson() {
        MediaType contentType = MediaType.parseMediaType("application/problem+json;charset=UTF-8");
        byte[] body = "{\"status\":400,\"detail\":\"invalid input\"}".getBytes(StandardCharsets.UTF_8);

        Optional<ProblemDetail> problemDetail = reader.read(contentType, body);

        assertThat(problemDetail).isPresent();
    }
}
