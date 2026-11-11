package com.trust.security.web.problem;

import com.trust.web.problem.ProblemDetailsWriter;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;
import java.util.Objects;

public final class ProblemDetailsAuthenticationEntryPoint
        implements AuthenticationEntryPoint {

    private final AuthenticationEntryPoint delegate;
    private final ProblemDetailsWriter problemDetailsWriter;

    public ProblemDetailsAuthenticationEntryPoint(
            AuthenticationEntryPoint delegate,
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
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authenticationException)
            throws IOException, ServletException {

        delegate.commence(
                request,
                response,
                authenticationException
        );

        problemDetailsWriter.write(
                request,
                response,
                "Authentication is required to access this resource."
        );
    }
}