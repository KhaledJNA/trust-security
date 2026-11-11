package com.trust.security.resourceserver.multichain;

/**
 * Thrown at startup by {@link MultiChainCoexistenceCondition} when this
 * starter and {@code trust-security-oauth2-client-starter} are both on the
 * classpath without a valid multiple {@code SecurityFilterChain} setup.
 * Rendered by {@link MultiChainConfigurationFailureAnalyzer}.
 */
public final class MultiChainConfigurationException extends RuntimeException {

    private final String action;

    private MultiChainConfigurationException(String description, String action) {
        super(description);
        this.action = action;
    }

    String getAction() {
        return action;
    }

    static MultiChainConfigurationException notDeclared() {
        return new MultiChainConfigurationException(
                "trust-security-resource-server-starter and trust-security-oauth2-client-starter are both "
                        + "on the classpath, but multiple-SecurityFilterChain mode is not declared on both "
                        + "sides. Each starter installs its own SecurityFilterChain: without an explicit, "
                        + "disjoint URL split, only one of them would ever handle requests.",
                "Either keep only one of the two starters, or set both "
                        + MultiChainCoexistenceCondition.OWN_REQUEST_PATTERN_PROPERTY + " and "
                        + MultiChainCoexistenceCondition.OAUTH2_CLIENT_REQUEST_PATTERN_PROPERTY
                        + " to two non-overlapping patterns that together cover every path the "
                        + "application serves.");
    }

    static MultiChainConfigurationException overlapping(String ownPattern, String oauth2ClientPattern) {
        return new MultiChainConfigurationException(
                "%s ('%s') and %s ('%s') overlap: Spring Security would silently pick one chain for the ambiguous paths."
                        .formatted(MultiChainCoexistenceCondition.OWN_REQUEST_PATTERN_PROPERTY, ownPattern,
                                MultiChainCoexistenceCondition.OAUTH2_CLIENT_REQUEST_PATTERN_PROPERTY,
                                oauth2ClientPattern),
                "Choose two non-overlapping patterns, for example /api/** for the resource server and "
                        + "/app/** for the OAuth2 client. A pattern that contains the other (such as /**) "
                        + "is always rejected.");
    }
}
