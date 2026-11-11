package com.trust.security.client.multichain;

import org.springframework.boot.diagnostics.AbstractFailureAnalyzer;
import org.springframework.boot.diagnostics.FailureAnalysis;

/**
 * Turns {@link MultiChainConfigurationException} into a readable
 * "Description / Action" startup report. Registered in
 * {@code META-INF/spring.factories}.
 */
public final class MultiChainConfigurationFailureAnalyzer
        extends AbstractFailureAnalyzer<MultiChainConfigurationException> {

    @Override
    protected FailureAnalysis analyze(Throwable rootFailure, MultiChainConfigurationException cause) {
        return new FailureAnalysis(cause.getMessage(), cause.getAction(), cause);
    }
}
