package com.trust.security.client.authorities;

import com.trust.security.core.role.AuthorityClaimMapping;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Declares, from the application's own configuration, which claims carry
 * authorities and which prefix to apply to them.
 *
 * <p>Provider-neutral by design: without any {@code mappings} entry, no
 * business authority is extracted (native Spring/OIDC authorities, e.g.
 * {@code OIDC_USER}, are unaffected, since they never go through this
 * mechanism). Applications backed by an identity provider that exposes
 * proprietary role claims under provider-specific paths are expected to
 * declare the matching mappings explicitly.
 */
@ConfigurationProperties(prefix = "trust.security.authorities")
public class AuthoritiesMappingProperties {

    /**
     * Ordered list of claim-to-authority mappings applied on top of the
     * provider's native authorities. Each entry declares a {@code path} into
     * the ID token/userinfo claim set and the {@code prefix} to apply to
     * every value found there (see {@link AuthorityClaimMapping}). Optional:
     * defaults to an empty list, in which case no business authority is
     * extracted from provider claims (native Spring/OIDC authorities, e.g.
     * {@code OIDC_USER}, are unaffected, since they never go through this
     * mechanism).
     */
    private List<AuthorityClaimMapping> mappings = List.of();

    public List<AuthorityClaimMapping> getMappings() {
        return mappings;
    }

    public void setMappings(List<AuthorityClaimMapping> mappings) {
        this.mappings = mappings;
    }
}
