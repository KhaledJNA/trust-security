package com.trust.security.resourceserver.tokenformat;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Turns {@link MissingTokenFormatException} into a readable "Description /
 * Action" startup report instead of a raw stack trace, registered via
 * {@code META-INF/spring.factories}.
 */
public final class MissingTokenFormatFailureAnalyzer extends AbstractFailureAnalyzer<MissingTokenFormatException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, MissingTokenFormatException cause) {
        return new FailureAnalysis(
                MissingTokenFormatException.DESCRIPTION,
                MissingTokenFormatException.ACTION,
                cause);
    }
}
