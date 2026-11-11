package com.trust.integration.support.oauth2client;

import com.trust.security.resourceserver.ResourceServerAutoConfiguration;
import com.trust.keycloak.authorization.KeycloakAuthorizationAutoConfiguration;
import com.trust.security.core.acr.RequiresAcr;
import com.trust.security.core.user.AuthenticatedUser;
import com.trust.security.core.user.CurrentAuthoritiesProvider;
import com.trust.security.core.user.CurrentUserProvider;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * The "real BFF" that {@code trust-security-oauth2-client-starter} is
 * exercised through - a plain Spring Boot app declaring the starter as any
 * real BFF would, with purely technical endpoints and no vocabulary borrowed
 * from any demo application. No test-only shortcut lives in this class: the
 * identity it exposes always comes from whatever the real security filter
 * chain put in the {@code SecurityContext}.
 */
@SpringBootApplication(exclude = {ResourceServerAutoConfiguration.class, KeycloakAuthorizationAutoConfiguration.class})
public class OAuth2ClientHarnessApplication {

    @RestController
    static class IdentityController {

        private final CurrentUserProvider currentUserProvider;
        private final CurrentAuthoritiesProvider currentAuthoritiesProvider;

        IdentityController(CurrentUserProvider currentUserProvider, CurrentAuthoritiesProvider currentAuthoritiesProvider) {
            this.currentUserProvider = currentUserProvider;
            this.currentAuthoritiesProvider = currentAuthoritiesProvider;
        }

        @GetMapping("/identity")
        Map<String, Object> identity() {
            Optional<AuthenticatedUser> currentUser = currentUserProvider.getCurrentUser();
            List<String> authorities = currentAuthoritiesProvider.getAuthorities().stream().toList();

            // Not Map.of: username/subject may legitimately be absent (null).
            Map<String, Object> identity = new LinkedHashMap<>();
            identity.put("authenticated", currentUser.isPresent());
            identity.put("subject", currentUser.map(AuthenticatedUser::subject).orElse(null));
            identity.put("username", currentUser.map(AuthenticatedUser::username).orElse(null));
            identity.put("authorities", authorities);
            return identity;
        }

        @GetMapping("/identity/claims")
        Map<String, Object> claims() {
            Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            if (principal instanceof OidcUser oidcUser) {
                return oidcUser.getClaims();
            }
            return Map.of("principalType", principal.getClass().getName());
        }

        @GetMapping("/strong")
        @RequiresAcr("strong")
        String strong() {
            return "granted";
        }
    }

    public static void main(String[] args) {
        org.springframework.boot.SpringApplication.run(OAuth2ClientHarnessApplication.class, args);
    }
}
