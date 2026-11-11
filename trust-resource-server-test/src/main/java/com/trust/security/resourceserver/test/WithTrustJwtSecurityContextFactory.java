package com.trust.security.resourceserver.test;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.Collection;
import java.util.Map;

/**
 * Instantiated by {@code spring-security-test} through the test's own
 * {@code ApplicationContext} (see {@code WithSecurityContextTestExecutionListener}),
 * which is what makes the {@link Autowired} field below resolve to the
 * application's real authorities converter bean - not a module-provided
 * substitute.
 */
public class WithTrustJwtSecurityContextFactory implements WithSecurityContextFactory<WithTrustJwt> {

    @Autowired(required = false)
    private @Nullable Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter;

    @Override
    public SecurityContext createSecurityContext(WithTrustJwt annotation) {
        if (authoritiesConverter == null) {
            throw new IllegalStateException(
                    "@WithTrustJwt requires a Converter<Jwt, Collection<GrantedAuthority>> bean in the test's "
                            + "Spring context - the same one the resource server's real security configuration "
                            + "builds - so it can exercise the application's real claims-to-authorities mapping. "
                            + "None was found: is trust-security-resource-server-starter's auto-configuration "
                            + "actually loaded in this test's context?");
        }

        Map<String, Object> claims = TrustTestJwts.loadClaims(annotation.value());
        String subjectOverride = annotation.subject().isBlank() ? null : annotation.subject();
        Jwt jwt = TrustTestJwts.jwt(claims, subjectOverride);

        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        AbstractAuthenticationToken authentication = jwtAuthenticationConverter.convert(jwt);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }
}
