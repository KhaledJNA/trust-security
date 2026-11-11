package com.trust.security.client.tenant;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

/**
 * Login-related properties for the BFF's {@code oauth2Login()} flow, distinct
 * from {@link com.trust.security.client.OAuth2ClientSecurityProperties}'s broader {@code trust.security}
 * root - these settle how a login is *initiated*, not the client/session/logout
 * wiring the root class covers.
 */
@Validated
@ConfigurationProperties(prefix = "trust.security.oauth2-client.login")
public class OAuth2LoginProperties {

    /**
     * Resolves which Spring {@code registrationId} to use for a login request
     * that does not itself name one (i.e. does not call
     * {@code /oauth2/authorization/{registrationId}} directly) - typically a
     * tenant-specific login path or host. Optional, {@code null} by default:
     * this whole mechanism is inactive unless this section is explicitly
     * configured with at least a {@code request-pattern}.
     */
    @Valid
    private RegistrationIdResolution registrationIdResolution;

    public RegistrationIdResolution getRegistrationIdResolution() {
        return registrationIdResolution;
    }

    public void setRegistrationIdResolution(RegistrationIdResolution registrationIdResolution) {
        this.registrationIdResolution = registrationIdResolution;
    }

    public static class RegistrationIdResolution {

        /**
         * The request path this mechanism reacts to - never
         * {@code /oauth2/authorization/**} itself, which stays entirely
         * Spring's own. For {@link Source#PATH}, must contain the
         * {@code {variable-name}} template segment (e.g. {@code /sso/login/{tenant}}).
         * For {@link Source#HOST}, a plain path with no template variable
         * (e.g. {@code /sso/login}) - the discriminating value comes from the
         * request's host instead.
         */
        @NotBlank(message = "trust.security.oauth2-client.login.registration-id-resolution.request-pattern "
                + "is required once this section is configured")
        private String requestPattern;

        /**
         * Where the discriminating value comes from: the request's host
         * ({@link Source#HOST}), or a path variable extracted from
         * {@link #requestPattern} ({@link Source#PATH}).
         */
        @NotNull(message = "trust.security.oauth2-client.login.registration-id-resolution.source is required "
                + "(host or path)")
        private Source source;

        /**
         * The path variable name to extract from {@link #requestPattern}.
         * Required, and only meaningful, when {@link #source} is
         * {@link Source#PATH}.
         */
        private String variableName;

        /**
         * Closed allowlist: the extracted value (host, or path variable) must
         * match a key here exactly to resolve to a {@code registrationId}. No
         * wildcard, no suffix matching, no fallback for an unlisted value.
         * Every value here is validated at startup against the real
         * {@code ClientRegistrationRepository} - a typo here fails the
         * application immediately, never at first login attempt.
         */
        @NotEmpty(message = "trust.security.oauth2-client.login.registration-id-resolution.mappings must not "
                + "be empty once this section is configured")
        private Map<String, String> mappings = Map.of();

        public String getRequestPattern() {
            return requestPattern;
        }

        public void setRequestPattern(String requestPattern) {
            this.requestPattern = requestPattern;
        }

        public Source getSource() {
            return source;
        }

        public void setSource(Source source) {
            this.source = source;
        }

        public String getVariableName() {
            return variableName;
        }

        public void setVariableName(String variableName) {
            this.variableName = variableName;
        }

        public Map<String, String> getMappings() {
            return mappings;
        }

        public void setMappings(Map<String, String> mappings) {
            this.mappings = mappings == null ? Map.of() : mappings;
        }
    }

    public enum Source {
        HOST,
        PATH
    }
}
