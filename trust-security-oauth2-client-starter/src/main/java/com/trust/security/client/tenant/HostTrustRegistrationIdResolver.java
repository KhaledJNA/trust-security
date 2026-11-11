package com.trust.security.client.tenant;

import jakarta.servlet.http.HttpServletRequest;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves a {@code registrationId} from the request's host - {@link HttpServletRequest#getServerName()},
 * never the raw {@code Host}/{@code X-Forwarded-Host} header: the servlet
 * container (and, behind a reverse proxy, Spring Boot's own {@code ForwardedHeaderFilter},
 * activated by the application via {@code server.forward-headers-strategy})
 * is what decides whether a forwarded header is trusted - this resolver never
 * makes that decision itself.
 * <p>
 * Comparison is exact and case-insensitive (hostnames are case-insensitive
 * per RFC 4343); {@code getServerName()} already excludes the port, so a port
 * never affects resolution.
 */
final class HostTrustRegistrationIdResolver implements TrustRegistrationIdResolver {

    private final Map<String, String> registrationIdsByHost;

    HostTrustRegistrationIdResolver(Map<String, String> mappings) {
        Map<String, String> normalized = new LinkedHashMap<>();
        mappings.forEach((host, registrationId) -> normalized.put(normalize(host), registrationId));
        this.registrationIdsByHost = Map.copyOf(normalized);
    }

    @Override
    public Optional<String> resolve(HttpServletRequest request) {
        String host = request.getServerName();
        if (host == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(registrationIdsByHost.get(normalize(host)));
    }

    private static String normalize(String host) {
        return host.toLowerCase(Locale.ROOT);
    }
}
