package com.trust.security.resourceserver.tokenformat;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Turns {@link AmbiguousTokenFormatException} into a readable "Description /
 * Action" startup report instead of a raw stack trace, registered via
 * {@code META-INF/spring.factories}.
 */
public final class AmbiguousTokenFormatFailureAnalyzer extends AbstractFailureAnalyzer<AmbiguousTokenFormatException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, AmbiguousTokenFormatException cause) {
        return new FailureAnalysis(
                AmbiguousTokenFormatException.DESCRIPTION,
                AmbiguousTokenFormatException.ACTION,
                cause);
    }
}
