package com.trust.security.web.async;

import org.jspecify.annotations.Nullable;
import org.springframework.core.task.TaskDecorator;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;

/**
 * Propagates the security and request contexts to asynchronous tasks.
 *
 * <p>Both contexts are thread-bound: without propagation, an {@code @Async}
 * method loses the authenticated principal, and outgoing calls are issued
 * without a bearer token.
 *
 * <p>The request context is required by session-backed token stores, where the
 * access token is resolved through the current HTTP session rather than from
 * the security context itself. It is only usable while the request is still
 * in progress: a task that outlives the request cannot rely on it.
 *
 * <p>The task runs with its own copy of the security context: a later change
 * on the submitting thread (for example a logout clearing the authentication)
 * does not affect a task already submitted. Whatever contexts the executing
 * thread had before are restored afterwards, which matters when the task runs
 * on the caller's own thread (e.g. {@code CallerRunsPolicy}).
 */
public class SecurityContextTaskDecorator implements TaskDecorator {

    @Override
    public Runnable decorate(Runnable runnable) {
        SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
        securityContext.setAuthentication(SecurityContextHolder.getContext().getAuthentication());
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();

        return () -> {
            SecurityContext previousContext = SecurityContextHolder.getContext();
            RequestAttributes previousAttributes = RequestContextHolder.getRequestAttributes();
            try {
                SecurityContextHolder.setContext(securityContext);
                setRequestAttributes(requestAttributes);
                runnable.run();
            } finally {
                SecurityContextHolder.setContext(previousContext);
                setRequestAttributes(previousAttributes);
            }
        };
    }

    private static void setRequestAttributes(@Nullable RequestAttributes attributes) {
        if (attributes != null) {
            RequestContextHolder.setRequestAttributes(attributes);
        } else {
            RequestContextHolder.resetRequestAttributes();
        }
    }
}
