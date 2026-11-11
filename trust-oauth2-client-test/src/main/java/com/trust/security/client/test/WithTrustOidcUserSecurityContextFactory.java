package com.trust.security.client.test;

import org.jspecify.annotations.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.test.context.support.WithSecurityContextFactory;

import java.util.Map;

/**
 * Instantiated by {@code spring-security-test} through the test's own
 * {@code ApplicationContext}, which is what makes the {@link Autowired} field
 * below resolve to the application's real authorities mapper bean - not a
 * module-provided substitute. The field is optional: without a mapper bean in
 * context, only the raw {@code OIDC_USER} authority is granted (see
 * {@link TrustTestOidcUsers#authenticationToken}).
 */
public class WithTrustOidcUserSecurityContextFactory implements WithSecurityContextFactory<WithTrustOidcUser> {

    @Autowired(required = false)
    private @Nullable GrantedAuthoritiesMapper authoritiesMapper;

    @Override
    public SecurityContext createSecurityContext(WithTrustOidcUser annotation) {
        Map<String, Object> claims = TrustTestOidcUsers.loadClaims(annotation.value());
        String subjectOverride = annotation.subject().isBlank() ? null : annotation.subject();
        String acrOverride = annotation.acr().isBlank() ? null : annotation.acr();

        OAuth2AuthenticationToken authentication = TrustTestOidcUsers.authenticationToken(
                claims, subjectOverride, acrOverride, annotation.registrationId(), authoritiesMapper);

        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(authentication);
        return context;
    }
}
