package com.trust.security.core.authorization;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.Authentication;

import java.util.Map;
import java.util.Objects;

/**
 * Provider-neutral description of an authorization decision to make.
 * <p>
 * Carries no notion of any specific identity provider or authorization
 * protocol - no bearer token, no vendor-specific wire vocabulary.
 * An {@link AuthorizationDecisionClient} adapter decides for itself what it
 * needs from {@code authentication}: one adapter might extract a token from
 * it, another might read roles or attributes instead.
 *
 * @param authentication the caller's authentication; may be {@code null} or
 *                        of a type an adapter does not support - adapters are
 *                        expected to deny rather than throw in that case
 * @param resource        the resource being accessed (from {@code @RequiresPermission(resource = ...)})
 * @param action          the action being attempted (from {@code @RequiresPermission(scope = ...)});
 *                         named {@code action} here, deliberately provider-neutral,
 *                         even though the public annotation keeps calling it {@code scope}
 * @param context          additional attributes for the decision; never {@code null}
 */
public record AuthorizationRequest(
        @Nullable Authentication authentication,
        String resource,
        String action,
        Map<String, String> context) {

    public AuthorizationRequest {
        Objects.requireNonNull(resource, "resource must not be null");
        Objects.requireNonNull(action, "action must not be null");
        context = context == null ? Map.of() : Map.copyOf(context);
    }
}
