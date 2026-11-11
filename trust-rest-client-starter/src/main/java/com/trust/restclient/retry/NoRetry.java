package com.trust.restclient.retry;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Marks a single HTTP service interface method as never retried,
 * regardless of its group's retry configuration.
 *
 * <p>{@code PUT}/{@code DELETE} are idempotent in the HTTP sense - repeating
 * them leaves the target resource in the same end state - but that does not
 * guarantee every side effect the endpoint produces is itself safe to
 * duplicate (an audit log entry, a notification, a downstream event).
 * Annotate such a method with {@code @NoRetry} to opt it out individually,
 * while leaving the rest of the same client's methods retried normally.
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.METHOD)
public @interface NoRetry {
}
