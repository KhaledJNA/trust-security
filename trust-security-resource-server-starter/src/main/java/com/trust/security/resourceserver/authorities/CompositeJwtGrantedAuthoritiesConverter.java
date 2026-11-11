package com.trust.security.resourceserver.authorities;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Objects;
import java.util.Set;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * Runs two {@code Converter<Jwt, Collection<GrantedAuthority>>} instances and
 * merges their results, deduplicating equal authorities.
 * <p>
 * Used to compose Spring Security's own default {@code JwtGrantedAuthoritiesConverter}
 * (which extracts standard {@code SCOPE_*} authorities from the {@code scope}/
 * {@code scp} claim) with {@link JwtClaimAuthoritiesConverter} (Trust's
 * generic, configuration-driven claim mapping) - rather than replacing the
 * former with the latter, which would silently drop scope-based authorities
 * for any application that has not configured {@code trust.security.authorities.mappings}.
 * <p>
 * Deduplication relies on {@link GrantedAuthority} implementations (in
 * practice {@code SimpleGrantedAuthority} on both sides) having value-based
 * {@code equals}/{@code hashCode} on the authority string.
 */
public final class CompositeJwtGrantedAuthoritiesConverter
        implements Converter<Jwt, Collection<GrantedAuthority>> {

    private final Converter<Jwt, Collection<GrantedAuthority>> first;
    private final Converter<Jwt, Collection<GrantedAuthority>> second;

    public CompositeJwtGrantedAuthoritiesConverter(
            Converter<Jwt, Collection<GrantedAuthority>> first,
            Converter<Jwt, Collection<GrantedAuthority>> second) {

        this.first = Objects.requireNonNull(first, "first must not be null");
        this.second = Objects.requireNonNull(second, "second must not be null");
    }

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> merged = new LinkedHashSet<>();

        Collection<GrantedAuthority> firstResult = first.convert(jwt);
        if (firstResult != null) {
            merged.addAll(firstResult);
        }

        Collection<GrantedAuthority> secondResult = second.convert(jwt);
        if (secondResult != null) {
            merged.addAll(secondResult);
        }

        return merged;
    }
}
