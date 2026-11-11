package com.trust.web.correlation;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

import static com.trust.web.correlation.CorrelationId.HEADER_NAME;
import static com.trust.web.correlation.CorrelationId.MDC_KEY;


public final class CorrelationIdFilter extends OncePerRequestFilter {


    private static final int MAX_LENGTH = 128;

    private static final Pattern VALID_VALUE =
            Pattern.compile("[A-Za-z0-9._:-]+");

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain)
            throws ServletException, IOException {

        String correlationId =
                resolveCorrelationId(request.getHeader(HEADER_NAME));

        response.setHeader(HEADER_NAME, correlationId);
        MDC.put(MDC_KEY, correlationId);

        try {
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY);
        }
    }

    private String resolveCorrelationId(String candidate) {
        if (isValid(candidate)) {
            return candidate;
        }

        return UUID.randomUUID().toString();
    }

    private boolean isValid(String value) {
        return value != null
                && !value.isBlank()
                && value.length() <= MAX_LENGTH
                && VALID_VALUE.matcher(value).matches();
    }
}