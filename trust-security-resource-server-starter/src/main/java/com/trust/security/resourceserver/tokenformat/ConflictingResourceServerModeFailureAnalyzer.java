package com.trust.security.resourceserver.tokenformat;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Turns {@link ConflictingResourceServerModeException} into a readable
 * "Description / Action" startup report instead of a raw stack trace,
 * registered via {@code META-INF/spring.factories}.
 */
public final class ConflictingResourceServerModeFailureAnalyzer
        extends AbstractFailureAnalyzer<ConflictingResourceServerModeException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, ConflictingResourceServerModeException cause) {
        return new FailureAnalysis(
                cause.getMessage(),
                ConflictingResourceServerModeException.ACTION,
                cause);
    }
}
