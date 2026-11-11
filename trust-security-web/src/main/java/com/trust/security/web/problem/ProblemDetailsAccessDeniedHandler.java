package com.trust.security.web.problem;

import com.trust.web.problem.ProblemDetailsWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;
import java.util.Objects;

public final class ProblemDetailsAccessDeniedHandler
        implements AccessDeniedHandler {

    private final AccessDeniedHandler delegate;
    private final ProblemDetailsWriter problemDetailsWriter;

    public ProblemDetailsAccessDeniedHandler(
            AccessDeniedHandler delegate,
            ProblemDetailsWriter problemDetailsWriter) {

        this.delegate = Objects.requireNonNull(
                delegate,
                "delegate must not be null"
        );

        this.problemDetailsWriter = Objects.requireNonNull(
                problemDetailsWriter,
                "problemDetailsWriter must not be null"
        );
    }

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException accessDeniedException)
            throws IOException, ServletException {

        delegate.handle(
                request,
                response,
                accessDeniedException
        );

        problemDetailsWriter.write(
                request,
                response,
                "Access is denied."
        );
    }
}