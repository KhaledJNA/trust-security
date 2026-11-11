package com.trust.restclient.correlation;

import com.trust.web.correlation.CorrelationId;
import org.slf4j.MDC;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;

import java.io.IOException;
import java.util.UUID;

/**
 * Propagates the correlation identifier on every outgoing call.
 *
 * <p>Normally, the MDC already carries one - posed by
 * {@code CorrelationIdFilter} on the current incoming request. This
 * interceptor never overwrites that value: an application that wants every
 * outgoing call of a batch/worker run to share one identifier sets it
 * itself, once, at the start of the run.
 *
 * <p>When the MDC carries none - a batch, with no incoming request to
 * have populated it - this interceptor generates one, propagates it on this
 * call, and holds it in the MDC for the duration of the call only (so it
 * shows up in this call's own log lines), restoring the MDC's prior state -
 * absence, not a leftover value - once the call returns. A value generated
 * this way is deliberately <em>not</em> left behind in the MDC: this
 * interceptor has no way to know whether the surrounding code intends the
 * next outgoing call to share the same run, or start a new one, so it never
 * assumes either.
 */
public final class CorrelationIdClientHttpRequestInterceptor
        implements ClientHttpRequestInterceptor {

    @Override
    public ClientHttpResponse intercept(
            HttpRequest request,
            byte[] body,
            ClientHttpRequestExecution execution)
            throws IOException {

        String existing = MDC.get(CorrelationId.MDC_KEY);
        if (existing != null && !existing.isBlank()) {
            request.getHeaders().set(CorrelationId.HEADER_NAME, existing);
            return execution.execute(request, body);
        }

        String generated = UUID.randomUUID().toString();
        request.getHeaders().set(CorrelationId.HEADER_NAME, generated);
        MDC.put(CorrelationId.MDC_KEY, generated);
        try {
            return execution.execute(request, body);
        } finally {
            MDC.remove(CorrelationId.MDC_KEY);
        }
    }
}
