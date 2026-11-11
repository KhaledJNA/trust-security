package com.trust.security.resourceserver;

import com.trust.security.resourceserver.jwt.IssuerProperties;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
@ConfigurationProperties(prefix = "trust.security.resource-server")
public class ResourceServerSecurityProperties {

    /**
     * The identifier this Resource Server is registered as with the
     * provider. Used for two purposes: validating that a presented token was
     * actually issued for this API - its expected {@code aud} claim - and,
     * when a client-role authority mapping references the
     * {@code {clientId}} placeholder (e.g.
     * {@code resource_access.{clientId}.roles} for Keycloak), resolving that
     * placeholder. Required: no default value: without it, this API would
     * accept a token issued for any client in the realm.
     */
    @NotBlank(message = "trust.security.resource-server.client-id is required: without it, this API "
            + "would accept any token issued by the realm")
    private String clientId;

    /** Application-specific public paths, added to the starter's defaults. */
    private List<String> publicPaths = List.of();

    /**
     * Trusted issuer allowlist for multi-issuer JWT mode. Empty by default -
     * mode is active only when this collection is explicitly configured with
     * at least one entry, and is mutually exclusive with the single-issuer
     * {@code spring.security.oauth2.resourceserver.jwt.issuer-uri} and
     * opaque-token {@code ...opaquetoken.introspection-uri} properties (see
     * {@code ResourceServerAutoConfiguration.tokenFormatGuard}).
     */
    private List<@Valid IssuerProperties> issuers = List.of();


    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    public List<IssuerProperties> getIssuers() {
        return issuers;
    }

    public void setIssuers(List<IssuerProperties> issuers) {
        this.issuers = issuers == null ? List.of() : issuers;
    }
}