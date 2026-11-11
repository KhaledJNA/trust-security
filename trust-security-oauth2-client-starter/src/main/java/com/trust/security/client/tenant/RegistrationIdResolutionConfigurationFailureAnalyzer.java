package com.trust.security.client.tenant;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Turns {@link RegistrationIdResolutionConfigurationException} into a
 * readable "Description / Action" startup report instead of a raw stack
 * trace, registered via {@code META-INF/spring.factories}.
 */
public final class RegistrationIdResolutionConfigurationFailureAnalyzer
        extends AbstractFailureAnalyzer<RegistrationIdResolutionConfigurationException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, RegistrationIdResolutionConfigurationException cause) {
        return new FailureAnalysis(cause.getMessage(), cause.getAction(), cause);
    }
}
