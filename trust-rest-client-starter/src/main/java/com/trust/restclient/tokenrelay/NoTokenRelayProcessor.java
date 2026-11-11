package com.trust.restclient.tokenrelay;

import org.jspecify.annotations.Nullable;
import org.springframework.core.MethodParameter;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.HttpRequest;
import org.springframework.web.service.invoker.HttpRequestValues;

import java.lang.reflect.Method;

/**
 * Marks a request as opted out of resource-server token relay, on the same
 * generic channel {@code ClientRegistrationIdProcessor}/{@code NoRetryProcessor}
 * use ({@link HttpRequestValues.Builder#configureAttributes}) - an
 * annotation read once, at proxy-invocation time, and carried as a request
 * attribute to {@link com.trust.restclient.ResourceServerTokenRelayInterceptor}.
 *
 * <p>Checks both the method and its declaring interface, unlike
 * {@code NoRetryProcessor} (method-only): {@link NoTokenRelay} is meant to
 * apply per-client as well as per-method.
 */
public final class NoTokenRelayProcessor implements HttpRequestValues.Processor {

    public static final NoTokenRelayProcessor INSTANCE = new NoTokenRelayProcessor();

    private static final String NO_TOKEN_RELAY_ATTRIBUTE = NoTokenRelayProcessor.class.getName() + ".NO_TOKEN_RELAY";

    private NoTokenRelayProcessor() {
    }

    @Override
    public void process(Method method, MethodParameter[] parameters, @Nullable Object[] arguments,
            HttpRequestValues.Builder builder) {

        if (AnnotatedElementUtils.hasAnnotation(method, NoTokenRelay.class)
                || AnnotatedElementUtils.hasAnnotation(method.getDeclaringClass(), NoTokenRelay.class)) {
            builder.configureAttributes(attributes -> attributes.put(NO_TOKEN_RELAY_ATTRIBUTE, Boolean.TRUE));
        }
    }

    /** Whether the intercepted request's method (or its declaring interface) was annotated {@link NoTokenRelay}. */
    public static boolean isSuppressed(HttpRequest request) {
        return Boolean.TRUE.equals(request.getAttributes().get(NO_TOKEN_RELAY_ATTRIBUTE));
    }
}
