package com.trust.security.core.authorization;

/**
 * A pluggable authorization decision point (PDP), providing a boolean
 * allow/deny answer for a provider-neutral {@link AuthorizationRequest}.
 * <p>
 * Implementations translate the request into whatever wire format or
 * protocol a specific authorization backend needs. This port itself carries
 * no such vocabulary.
 */
public interface AuthorizationDecisionClient {

    boolean isAllowed(AuthorizationRequest request);
}
