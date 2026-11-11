package com.trust.security.resourceserver.authorization;

import java.util.Map;
import java.util.Objects;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import com.trust.security.core.authorization.AuthorizationRequest;
import com.trust.security.core.authorization.PermissionChecker;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.core.Authentication;

/**
 * Provider-neutral {@link PermissionChecker}: builds a provider-neutral
 * {@link AuthorizationRequest} from its arguments and delegates the actual
 * authorization decision to whichever {@link AuthorizationDecisionClient}
 * adapter is configured by the application.
 * <p>
 * Carries no knowledge of any specific identity provider or authorization
 * protocol - not even of what kind of {@link Authentication} it is handed;
 * that decision belongs entirely to the configured adapter.
 * <p>
 * An {@link AuthorizationDecisionClient} is optional. When none is available,
 * this checker runs in <b>deny mode</b>: every {@code @RequiresPermission}
 * check is refused, with no network call and no exception - the same
 * {@code false} result an actual PDP would produce for a denied request, so
 * downstream error handling (RFC 9457 Problem Details) is unaffected. A
 * one-time {@code WARN} is logged when the checker is built without a client,
 * so the deny mode is visible at startup rather than only discovered through
 * a support ticket. This design deliberately never falls back to allowing
 * every check: a library-wide safety invariant is that no configuration, no
 * omission, and no auto-configuration ordering may make a
 * {@code @RequiresPermission}-annotated method callable without a control.
 * <p>
 * If more than one {@link AuthorizationDecisionClient} bean is present in the
 * application context, resolution fails fast at construction time
 * (propagating Spring's {@code NoUniqueBeanDefinitionException}, which names
 * the competing beans): two PDPs wired at once is a configuration error, not
 * a supported scenario, and must never be resolved by silently picking one.
 */
public final class ResourceServerPermissionChecker
        implements PermissionChecker {

    private static final Logger log =
            LoggerFactory.getLogger(ResourceServerPermissionChecker.class);

    private final @Nullable AuthorizationDecisionClient authorizationDecisionClient;

    public ResourceServerPermissionChecker(
            ObjectProvider<AuthorizationDecisionClient> authorizationDecisionClientProvider) {

        Objects.requireNonNull(
                authorizationDecisionClientProvider,
                "authorizationDecisionClientProvider must not be null"
        );

        this.authorizationDecisionClient =
                authorizationDecisionClientProvider.getIfAvailable();

        if (this.authorizationDecisionClient == null) {
            log.warn("Permission-based authorization is active in deny mode: no "
                    + "AuthorizationDecisionClient was found. Every method annotated "
                    + "@RequiresPermission will be refused until one is provided.");
        }
    }

    @Override
    public boolean isAllowed(
            Authentication authentication,
            String resource,
            String scope,
            Map<String, String> context) {

        if (authorizationDecisionClient == null) {
            return false;
        }

        return authorizationDecisionClient.isAllowed(
                new AuthorizationRequest(authentication, resource, scope, context)
        );
    }
}
