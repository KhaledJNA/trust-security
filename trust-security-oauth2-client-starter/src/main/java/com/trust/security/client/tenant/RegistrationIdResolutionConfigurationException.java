package com.trust.security.client.tenant;

/**
 * Thrown at startup for any misconfiguration of
 * {@code trust.security.oauth2-client.login.registration-id-resolution} that
 * would otherwise only surface at the first matching login attempt - a
 * {@code request-pattern} overlapping a Spring-managed OAuth2/OIDC endpoint,
 * a mapped {@code registrationId} absent from the real
 * {@code ClientRegistrationRepository}, or an inconsistent {@code source}/
 * {@code variable-name} combination. Each factory method below covers exactly
 * one such case, with a description and action specific to it - see
 * {@link RegistrationIdResolutionConfigurationFailureAnalyzer}.
 */
public final class RegistrationIdResolutionConfigurationException extends RuntimeException {

    private static final String PROPERTY_PREFIX =
            "trust.security.oauth2-client.login.registration-id-resolution";

    private final String action;

    private RegistrationIdResolutionConfigurationException(String description, String action) {
        super(description);
        this.action = action;
    }

    String getAction() {
        return action;
    }

    static RegistrationIdResolutionConfigurationException conflictingRequestPattern(
            String requestPattern, String conflictingWith) {

        return new RegistrationIdResolutionConfigurationException(
                ("%s.request-pattern ('%s') overlaps with %s, which Spring Security's own oauth2Login() "
                        + "already manages.")
                        .formatted(PROPERTY_PREFIX, requestPattern, conflictingWith),
                "Choose a request-pattern that does not overlap any Spring-managed OAuth2/OIDC endpoint "
                        + "(/oauth2/authorization/**, /login/oauth2/code/**, /logout/connect/back-channel/**, "
                        + "or this application's own logout-path).");
    }

    static RegistrationIdResolutionConfigurationException unknownRegistrationId(
            String mappedValue, String registrationId) {

        return new RegistrationIdResolutionConfigurationException(
                ("%s.mappings maps '%s' to registrationId '%s', which does not exist in "
                        + "spring.security.oauth2.client.registration.*.")
                        .formatted(PROPERTY_PREFIX, mappedValue, registrationId),
                "Fix the mapping to name an existing registrationId, or add the missing "
                        + "spring.security.oauth2.client.registration.<id> entry.");
    }

    static RegistrationIdResolutionConfigurationException missingVariableName() {
        return new RegistrationIdResolutionConfigurationException(
                ("%s.source is 'path' but variable-name is not set.").formatted(PROPERTY_PREFIX),
                "Set variable-name to the path template variable request-pattern declares "
                        + "(e.g. 'tenant' for /sso/login/{tenant}).");
    }

    static RegistrationIdResolutionConfigurationException variableNotInPattern(
            String requestPattern, String variableName) {

        return new RegistrationIdResolutionConfigurationException(
                ("%s.request-pattern ('%s') does not contain the '{%s}' template variable named by "
                        + "variable-name.")
                        .formatted(PROPERTY_PREFIX, requestPattern, variableName),
                ("Add '{%s}' to request-pattern, or fix variable-name to match the variable it actually "
                        + "declares.")
                        .formatted(variableName));
    }

    static RegistrationIdResolutionConfigurationException unexpectedVariableNameForHostSource() {
        return new RegistrationIdResolutionConfigurationException(
                ("%s.source is 'host', but variable-name is also set - it has no effect for this source "
                        + "and its presence likely signals a copy-paste mistake from path-based configuration.")
                        .formatted(PROPERTY_PREFIX),
                "Remove variable-name when source is 'host'.");
    }
}
