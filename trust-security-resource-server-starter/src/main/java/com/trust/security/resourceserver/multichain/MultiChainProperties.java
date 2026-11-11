package com.trust.security.resourceserver.multichain;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * URL scope of this starter's {@code SecurityFilterChain} when it runs in the
 * same application as {@code trust-security-oauth2-client-starter}
 * (multiple {@code SecurityFilterChain} mode).
 * <p>
 * Not set by default: the chain then applies to every request.
 */
@ConfigurationProperties(prefix = "trust.security.resource-server.multi-chain")
public class MultiChainProperties {

    /**
     * Request pattern handled by this starter's filter chain (e.g.
     * {@code /api/**}). Required, and must not overlap
     * {@code trust.security.oauth2-client.multi-chain.request-pattern},
     * when the OAuth2 client starter is also on the classpath.
     */
    private String requestPattern;

    public String getRequestPattern() {
        return requestPattern;
    }

    public void setRequestPattern(String requestPattern) {
        this.requestPattern = requestPattern;
    }
}
