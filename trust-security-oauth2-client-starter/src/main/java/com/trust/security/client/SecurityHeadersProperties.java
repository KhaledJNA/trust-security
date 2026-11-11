package com.trust.security.client;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Security-related HTTP response headers this application's own filter chain
 * (as configured by {@code trust-security-oauth2-client-starter}) can emit.
 * Distinct from {@link OAuth2ClientSecurityProperties}'s {@code trust.security}
 * root prefix because these settings are specific to headers, not to the
 * OAuth2/OIDC wiring itself.
 */
@ConfigurationProperties(prefix = "trust.security.oauth2-client.headers")
public class SecurityHeadersProperties {

    private final ContentSecurityPolicy contentSecurityPolicy =
            new ContentSecurityPolicy();

    public ContentSecurityPolicy getContentSecurityPolicy() {
        return contentSecurityPolicy;
    }

    public static class ContentSecurityPolicy {

        /**
         * Whether this application's own Content-Security-Policy header
         * should be emitted. Optional: defaults to {@code false} - the
         * starter never sends a CSP header on its own unless explicitly
         * enabled, since the right policy is application-specific.
         */
        private boolean enabled = false;

        /**
         * The Content-Security-Policy header value emitted when
         * {@link #enabled} is {@code true}. Optional: defaults to a
         * restrictive baseline ({@code default-src 'self'; frame-ancestors
         * 'none'; base-uri 'self'; object-src 'none'}), meant to be
         * overridden by applications that need to allow specific
         * script/style/asset origins.
         */
        private String policy =
                "default-src 'self'; " +
                "frame-ancestors 'none'; " +
                "base-uri 'self'; " +
                "object-src 'none'";

        public boolean isEnabled() {
            return enabled;
        }

        public void setEnabled(boolean enabled) {
            this.enabled = enabled;
        }

        public String getPolicy() {
            return policy;
        }

        public void setPolicy(String policy) {
            this.policy = policy;
        }
    }
}