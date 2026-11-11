package com.trust.security.client.authorities;

import com.trust.security.core.role.ClaimAuthoritiesMapper;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Plugs the generic, provider-neutral {@link ClaimAuthoritiesMapper} into
 * Spring Security's standard OAuth2 Login extension point.
 * <p>
 * This never inspects the access token: it only reads the claims Spring
 * Security itself already resolved for the user - {@link OAuth2UserAuthority#getAttributes()}
 * (and, for OIDC, its {@code OidcUserAuthority} subclass, whose attributes
 * are the ID Token claims merged with the UserInfo claims when a UserInfo
 * response was fetched, with the <b>ID Token taking precedence on a
 * conflicting key</b> - this is Spring Security's own merge order
 * ({@code OidcUserAuthority.collectClaims}), not a provider-specific rule).
 * OAuth2/OIDC does not guarantee the access token is a locally decodable
 * JWT, so it is never parsed here.
 * <p>
 * Authorities already produced by Spring (e.g. {@code OIDC_USER}) are always
 * preserved; authorities computed from claims are appended, with
 * deduplication on the resulting authority string.
 */
public class ClaimGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {

    private final ClaimAuthoritiesMapper claimAuthoritiesMapper;

    public ClaimGrantedAuthoritiesMapper(ClaimAuthoritiesMapper claimAuthoritiesMapper) {
        this.claimAuthoritiesMapper = Objects.requireNonNull(
                claimAuthoritiesMapper, "claimAuthoritiesMapper must not be null");
    }

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(
            Collection<? extends GrantedAuthority> authorities) {

        Set<String> seen = new LinkedHashSet<>();
        List<GrantedAuthority> mapped = new ArrayList<>();

        for (GrantedAuthority authority : authorities) {
            if (seen.add(authority.getAuthority())) {
                mapped.add(authority);
            }
        }

        for (GrantedAuthority authority : authorities) {
            if (authority instanceof OAuth2UserAuthority oauth2UserAuthority) {
                for (GrantedAuthority computed : claimAuthoritiesMapper.map(
                        oauth2UserAuthority.getAttributes(), Map.of())) {
                    if (seen.add(computed.getAuthority())) {
                        mapped.add(computed);
                    }
                }
            }
        }

        return List.copyOf(mapped);
    }
}
