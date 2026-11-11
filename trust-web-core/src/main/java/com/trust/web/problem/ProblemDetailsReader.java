package com.trust.web.problem;

import org.jspecify.annotations.Nullable;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.Objects;
import java.util.Optional;

/**
 * Parses an HTTP response body as a Problem Details (RFC 9457) document -
 * the exact wire format {@link ProblemDetailsWriter} produces - for use on
 * the calling side of an HTTP exchange.
 *
 * <p>Relies on the supplied {@code ObjectMapper} already carrying Spring's
 * {@code ProblemDetailJacksonMixin} - without it, {@code ProblemDetail}
 * still deserializes without error, but silently drops any RFC 9457
 * extension member (a field beyond the standard {@code type}/{@code title}/
 * {@code status}/{@code detail}/{@code instance}). Spring Boot's own
 * {@code JacksonAutoConfiguration} registers this mixin on the
 * auto-configured {@code ObjectMapper} whenever {@code ProblemDetail} is on
 * the classpath, so an application-provided mapper already has it; this
 * class does not register it a second time.
 */
public final class ProblemDetailsReader {

    private final ObjectMapper objectMapper;

    public ProblemDetailsReader(ObjectMapper objectMapper) {
        Objects.requireNonNull(objectMapper, "objectMapper must not be null");
        this.objectMapper = objectMapper;
    }

    /**
     * Parses {@code body} as a Problem Details document when {@code contentType}
     * is {@code application/problem+json} (or a compatible subtype/parameterized
     * variant). Returns empty for any other content type, an empty body, or a
     * body that does not parse as valid JSON - a response from a component that
     * doesn't speak Problem Details (a gateway, a proxy, a plain-text error
     * page) is not a parsing failure to surface, just an absence of structured
     * detail.
     */
    public Optional<ProblemDetail> read(@Nullable MediaType contentType, byte[] body) {
        if (body.length == 0 || !isProblemJson(contentType)) {
            return Optional.empty();
        }
        try {
            return Optional.ofNullable(objectMapper.readValue(body, ProblemDetail.class));
        } catch (JacksonException e) {
            return Optional.empty();
        }
    }

    private static boolean isProblemJson(@Nullable MediaType contentType) {
        return contentType != null && contentType.isCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON);
    }
}
