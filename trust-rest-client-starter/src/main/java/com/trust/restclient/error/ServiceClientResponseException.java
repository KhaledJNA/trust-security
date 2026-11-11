package com.trust.restclient.error;

import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.web.client.RestClientResponseException;

import java.nio.charset.Charset;
import java.util.Optional;

/**
 * A non-2xx response from a downstream service called through an
 * HTTP service group, enriched with the RFC 9457 Problem Details payload
 * the service returned, when it sent one - in addition to everything
 * {@link RestClientResponseException} already carries (status, headers, raw
 * body).
 */
public class ServiceClientResponseException extends RestClientResponseException {

    private final @Nullable ProblemDetail problemDetail;

    public ServiceClientResponseException(
            String message,
            HttpStatusCode statusCode,
            String statusText,
            @Nullable HttpHeaders headers,
            byte[] responseBody,
            @Nullable Charset responseCharset,
            @Nullable ProblemDetail problemDetail) {
        super(message, statusCode, statusText, headers, responseBody, responseCharset);
        this.problemDetail = problemDetail;
    }

    /** The Problem Details payload the downstream service returned, when it sent one. */
    public Optional<ProblemDetail> getProblemDetail() {
        return Optional.ofNullable(problemDetail);
    }
}
