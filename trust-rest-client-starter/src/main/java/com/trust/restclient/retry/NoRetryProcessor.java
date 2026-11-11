package com.trust.restclient.retry;

import org.jspecify.annotations.Nullable;
import org.springframework.core.MethodParameter;
import org.springframework.http.HttpRequest;
import org.springframework.web.service.invoker.HttpRequestValues;

import java.lang.reflect.Method;
import java.util.Map;

/**
 * Marks a request as opted out of retry, on the same generic channel
 * {@code ClientRegistrationIdProcessor} uses for {@code @ClientRegistrationId}
 * ({@link HttpRequestValues.Builder#configureAttributes}) - reused here
 * because it is exactly the mechanism needed: an annotation read once, at
 * proxy-invocation time, and carried as a request attribute to whichever
 * {@link org.springframework.http.client.ClientHttpRequestInterceptor} cares,
 * without any per-call reflection in the interceptor itself.
 *
 * <p>Replaces the previous {@code NoRetryAwareProxy}/{@code RetrySuppression}
 * pair (a JDK dynamic proxy plus a {@code ThreadLocal}) with a single request
 * attribute, read directly via {@link #isSuppressed(HttpRequest)}.
 */
public final class NoRetryProcessor implements HttpRequestValues.Processor {

    public static final NoRetryProcessor INSTANCE = new NoRetryProcessor();

    private static final String NO_RETRY_ATTRIBUTE = NoRetryProcessor.class.getName() + ".NO_RETRY";

    private NoRetryProcessor() {
    }

    @Override
    public void process(Method method, MethodParameter[] parameters, @Nullable Object[] arguments,
            HttpRequestValues.Builder builder) {

        if (method.isAnnotationPresent(NoRetry.class)) {
            builder.configureAttributes(attributes -> attributes.put(NO_RETRY_ATTRIBUTE, Boolean.TRUE));
        }
    }

    /** Whether the intercepted request's method was annotated {@link NoRetry}. */
    public static boolean isSuppressed(HttpRequest request) {
        return Boolean.TRUE.equals(request.getAttributes().get(NO_RETRY_ATTRIBUTE));
    }
}
