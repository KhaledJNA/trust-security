package com.trust.restclient.error;

import com.trust.web.problem.ProblemDetailsReader;
import org.jspecify.annotations.Nullable;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.web.client.ResponseErrorHandler;

import java.io.IOException;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Turns a non-2xx response from a downstream service into a
 * {@link ServiceClientResponseException} carrying its Problem Details
 * payload, when it sent one - replacing Spring's own default error handling
 * ({@code HttpClientErrorException}/{@code HttpServerErrorException}), which
 * only ever carries the raw response body.
 *
 * <p>Any status {@code 4xx}/{@code 5xx} is treated as an error uniformly -
 * this handler does not distinguish client from server errors with separate
 * exception types, since {@link ServiceClientResponseException#getStatusCode()}
 * already tells a caller that when it matters.
 */
public final class ProblemDetailsResponseErrorHandler implements ResponseErrorHandler {

    private final ProblemDetailsReader problemDetailsReader;

    public ProblemDetailsResponseErrorHandler(ProblemDetailsReader problemDetailsReader) {
        this.problemDetailsReader = Objects.requireNonNull(
                problemDetailsReader, "problemDetailsReader must not be null");
    }

    @Override
    public boolean hasError(ClientHttpResponse response) throws IOException {
        return response.getStatusCode().isError();
    }

    @Override
    public void handleError(URI url, HttpMethod method, ClientHttpResponse response) throws IOException {
        HttpStatusCode statusCode = response.getStatusCode();
        String statusText = response.getStatusText();
        HttpHeaders headers = response.getHeaders();
        byte[] body = response.getBody().readAllBytes();
        Charset charset = charsetOf(headers);
        ProblemDetail problemDetail = problemDetailsReader.read(headers.getContentType(), body).orElse(null);

        throw new ServiceClientResponseException(
                buildMessage(statusCode, statusText, url, method, body, charset, problemDetail),
                statusCode, statusText, headers, body, charset, problemDetail);
    }

    private static String buildMessage(
            HttpStatusCode statusCode, String statusText, URI url, HttpMethod method,
            byte[] body, @Nullable Charset charset, @Nullable ProblemDetail problemDetail) {

        StringBuilder message = new StringBuilder()
                .append(statusCode.value()).append(' ').append(statusText)
                .append(" on ").append(method).append(" request for \"").append(url).append('"')
                .append(": ");

        String detail = problemDetail != null ? problemDetail.getDetail() : null;
        if (detail != null) {
            message.append(detail);
        } else if (body.length > 0) {
            message.append(new String(body, charset != null ? charset : StandardCharsets.UTF_8));
        } else {
            message.append("[no body]");
        }
        return message.toString();
    }

    private static @Nullable Charset charsetOf(HttpHeaders headers) {
        MediaType contentType = headers.getContentType();
        return contentType != null ? contentType.getCharset() : null;
    }
}
