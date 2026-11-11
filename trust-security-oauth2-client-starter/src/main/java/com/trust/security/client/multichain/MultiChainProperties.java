package com.trust.security.client.multichain;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * URL scope of this starter's {@code SecurityFilterChain} when it runs in the
 * same application as {@code trust-security-resource-server-starter}
 * (multiple {@code SecurityFilterChain} mode).
 * <p>
 * Not set by default: the chain then applies to every request.
 */
@ConfigurationProperties(prefix = "trust.security.oauth2-client.multi-chain")
public class MultiChainProperties {

    /**
     * Request pattern handled by this starter's filter chain (e.g.
     * {@code /app/**}). Required, and must not overlap
     * {@code trust.security.resource-server.multi-chain.request-pattern},
     * when the resource-server starter is also on the classpath.
     */
    private String requestPattern;

    public String getRequestPattern() {
        return requestPattern;
    }

    public void setRequestPattern(String requestPattern) {
        this.requestPattern = requestPattern;
    }
}
