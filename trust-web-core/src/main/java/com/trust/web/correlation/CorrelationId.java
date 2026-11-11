package com.trust.web.correlation;

public final class CorrelationId {

    public static final String HEADER_NAME = "X-Correlation-ID";
    public static final String MDC_KEY = "correlationId";

    private CorrelationId() {
    }
}