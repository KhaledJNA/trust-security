package com.trust.security.resourceserver.authorities;

import com.trust.security.core.role.ClaimAuthoritiesMapper;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

/**
 * Adapts the generic {@link ClaimAuthoritiesMapper} to the {@link Converter}
 * contract expected by Spring Security's JWT authentication converter.
 *
 * <p>Carries no knowledge of any specific identity provider: which claims
 * hold authorities is entirely defined by the {@link ClaimAuthoritiesMapper}
 * mappings, configured by the application. The only thing this converter
 * contributes is the resource server's own client id, exposed to those
 * mappings as the {@code clientId} variable (e.g. for a
 * {@code "...{clientId}..."} path segment).
 */
public class JwtClaimAuthoritiesConverter
        implements Converter<Jwt, Collection<GrantedAuthority>> {

    private static final String CLIENT_ID_VARIABLE = "clientId";

    private final ClaimAuthoritiesMapper claimAuthoritiesMapper;
    private final String clientId;

    public JwtClaimAuthoritiesConverter(ClaimAuthoritiesMapper claimAuthoritiesMapper, String clientId) {
        this.claimAuthoritiesMapper = Objects.requireNonNull(
                claimAuthoritiesMapper, "claimAuthoritiesMapper must not be null");
        this.clientId = clientId;
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Map<String, String> variables = clientId == null
                ? Map.of()
                : Collections.singletonMap(CLIENT_ID_VARIABLE, clientId);
        return claimAuthoritiesMapper.map(jwt.getClaims(), variables);
    }
}
