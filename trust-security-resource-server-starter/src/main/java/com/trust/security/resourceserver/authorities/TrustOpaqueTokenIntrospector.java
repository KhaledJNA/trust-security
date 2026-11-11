package com.trust.security.resourceserver.authorities;

import com.trust.security.core.role.ClaimAuthoritiesMapper;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Decorates a delegate {@link OpaqueTokenIntrospector} to compose its
 * authorities with Trust's generic, configuration-driven {@link ClaimAuthoritiesMapper}
 * - never replacing them, as on the JWT side
 * ({@code CompositeJwtGrantedAuthoritiesConverter}).
 *
 * <p>The introspection response's attributes ({@link OAuth2AuthenticatedPrincipal#getAttributes()})
 * have the same shape ({@code Map<String, Object>}) as a JWT's claims, so the
 * same {@link ClaimAuthoritiesMapper} - and the same {@code trust.security.authorities.mappings}
 * configuration - applies unchanged, without a second mapping mechanism to
 * write or document.
 */
public class TrustOpaqueTokenIntrospector implements OpaqueTokenIntrospector {

    private static final String CLIENT_ID_VARIABLE = "clientId";

    private final OpaqueTokenIntrospector delegate;
    private final ClaimAuthoritiesMapper claimAuthoritiesMapper;
    private final String clientId;

    public TrustOpaqueTokenIntrospector(
            OpaqueTokenIntrospector delegate,
            ClaimAuthoritiesMapper claimAuthoritiesMapper,
            String clientId) {

        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.claimAuthoritiesMapper = Objects.requireNonNull(
                claimAuthoritiesMapper, "claimAuthoritiesMapper must not be null");
        this.clientId = clientId;
    }

    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal principal = delegate.introspect(token);

        Map<String, String> variables = clientId == null
                ? Map.of()
                : Collections.singletonMap(CLIENT_ID_VARIABLE, clientId);

        Set<GrantedAuthority> merged = new LinkedHashSet<>(principal.getAuthorities());
        merged.addAll(claimAuthoritiesMapper.map(principal.getAttributes(), variables));

        return new DefaultOAuth2AuthenticatedPrincipal(principal.getName(), principal.getAttributes(), merged);
    }
}
