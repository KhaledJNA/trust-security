package com.trust.security.test.authorization;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import com.trust.security.core.authorization.AuthorizationRequest;
import org.jspecify.annotations.Nullable;

import java.util.Deque;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.function.Predicate;

/**
 * Test double for {@link AuthorizationDecisionClient}: lets a test control the
 * PERMIT/DENY outcome for a given {@code (resource, action)} pair - and
 * optionally a {@code context} predicate - without starting Keycloak, UMA, OPA
 * or any other external policy decision point.
 *
 * <p>Registering this bean (see {@link TrustAuthorizationTestConfiguration})
 * lets the application's real {@code PermissionChecker} and
 * {@code RequiresPermissionAuthorizationManager} run unmodified: only the
 * outermost PDP boundary is replaced.
 *
 * <p>Rules are matched most-recently-registered-first, so a later call can
 * override an earlier one for the same resource/action. A request matching no
 * rule is denied (fail-closed) - this is a deliberate, explicit default, not
 * an oversight: an unconfigured permission check must not silently pass.
 */
public final class TestAuthorizationDecisionClient implements AuthorizationDecisionClient {

    private record Rule(String resource, String action, Predicate<Map<String, String>> contextMatcher, boolean allow) {

        boolean matches(AuthorizationRequest request) {
            return resource.equals(request.resource())
                    && action.equals(request.action())
                    && contextMatcher.test(request.context());
        }
    }

    private final Deque<Rule> rules = new ConcurrentLinkedDeque<>();
    private volatile @Nullable AuthorizationRequest lastRequest;

    public TestAuthorizationDecisionClient permit(String resource, String action) {
        return permit(resource, action, context -> true);
    }

    public TestAuthorizationDecisionClient permit(
            String resource, String action, Predicate<Map<String, String>> contextMatcher) {
        rules.addFirst(new Rule(resource, action, contextMatcher, true));
        return this;
    }

    public TestAuthorizationDecisionClient deny(String resource, String action) {
        return deny(resource, action, context -> true);
    }

    public TestAuthorizationDecisionClient deny(
            String resource, String action, Predicate<Map<String, String>> contextMatcher) {
        rules.addFirst(new Rule(resource, action, contextMatcher, false));
        return this;
    }

    /**
     * Clears every configured rule and the last observed request. Called
     * automatically after each test method by
     * {@link TestAuthorizationDecisionClientResetListener}.
     */
    public void reset() {
        rules.clear();
        lastRequest = null;
    }

    /** The last {@link AuthorizationRequest} this client was asked to decide, if any. */
    public Optional<AuthorizationRequest> lastRequest() {
        return Optional.ofNullable(lastRequest);
    }

    @Override
    public boolean isAllowed(AuthorizationRequest request) {
        lastRequest = request;
        for (Rule rule : rules) {
            if (rule.matches(request)) {
                return rule.allow();
            }
        }
        return false;
    }
}
