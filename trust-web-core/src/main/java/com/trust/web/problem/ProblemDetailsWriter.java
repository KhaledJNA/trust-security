package com.trust.web.problem;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public final class ProblemDetailsWriter {

    private final ObjectMapper objectMapper;

    public ProblemDetailsWriter(ObjectMapper objectMapper) {
        this.objectMapper = Objects.requireNonNull(
                objectMapper,
                "objectMapper must not be null"
        );
    }

    public void write(
            HttpServletRequest request,
            HttpServletResponse response,
            String detail) throws IOException {

        if (response.isCommitted()) {
            return;
        }

        int statusCode = response.getStatus();

        HttpStatusCode status =
                HttpStatusCode.valueOf(statusCode);

        ProblemDetail problemDetail =
                ProblemDetail.forStatusAndDetail(
                        status,
                        detail
                );

        HttpStatus httpStatus =
                HttpStatus.resolve(statusCode);

        if (httpStatus != null) {
            problemDetail.setTitle(
                    httpStatus.getReasonPhrase()
            );
        }

        problemDetail.setInstance(
                URI.create(request.getRequestURI())
        );

        response.setContentType(
                MediaType.APPLICATION_PROBLEM_JSON_VALUE
        );

        response.setCharacterEncoding(
                StandardCharsets.UTF_8.name()
        );

        objectMapper.writeValue(
                response.getOutputStream(),
                problemDetail
        );
    }
}