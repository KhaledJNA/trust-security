package com.trust.integration.support.resourceserver;

import com.trust.security.client.OAuth2ClientAutoConfiguration;
import com.trust.security.core.authorization.AuthorizationResourceId;
import com.trust.security.core.authorization.PermissionContextProvider;
import com.trust.security.core.authorization.RequiresPermission;
import com.trust.security.core.user.AuthenticatedUser;
import com.trust.security.core.user.CurrentUserProvider;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * The "real application" that {@code trust-security-resource-server-starter}
 * and {@code trust-security-keycloak-authorization-starter} are exercised
 * through - a plain Spring Boot app declaring these starters as any real
 * resource server would, with no test-only shortcut in its own code and no
 * vocabulary borrowed from any demo application. Used by every Resource
 * Server and Authorization/UMA contract test in this suite - which of the
 * two it is certifying for a given test is entirely a matter of which
 * {@code trust.security.resource-server.client-id} the test configures.
 */
@SpringBootApplication(exclude = OAuth2ClientAutoConfiguration.class)
public class ResourceServerHarnessApplication {

    /**
     * Reads the caller through Trust's {@link CurrentUserProvider}, never a
     * {@code Jwt}-typed principal, so the same endpoints serve the JWT and
     * the opaque-token (introspection) contract tests alike.
     */
    @RestController
    static class RoleProtectedController {

        private final CurrentUserProvider currentUserProvider;

        RoleProtectedController(CurrentUserProvider currentUserProvider) {
            this.currentUserProvider = currentUserProvider;
        }

        @GetMapping("/role-protected")
        @PreAuthorize("hasRole('TRUST_TEST_USER')")
        String roleProtected() {
            return subject();
        }

        /** The caller's username, through the same token-format-independent provider. */
        @GetMapping("/me")
        @PreAuthorize("hasRole('TRUST_TEST_USER')")
        String me() {
            return currentUserProvider.getCurrentUser()
                    .map(AuthenticatedUser::username)
                    .orElse("");
        }

        @GetMapping("/reader-protected")
        @PreAuthorize("hasRole('TRUST_TEST_READER')")
        String readerProtected() {
            return subject();
        }

        private String subject() {
            return currentUserProvider.getCurrentUser().map(AuthenticatedUser::subject).orElse("");
        }
    }

    @RestController
    static class AuthorizationController {

        @GetMapping("/resources/{id}")
        @RequiresPermission(resource = "TestResource", scope = "read")
        String read(@PathVariable Long id) {
            return "read:" + id;
        }

        @PutMapping("/resources/{id}")
        @RequiresPermission(resource = "TestResource", scope = "write")
        String write(
                @AuthorizationResourceId(TenantContextProvider.class)
                @PathVariable Long id) {
            return "write:" + id;
        }

        @GetMapping("/resources-unassigned/{id}")
        @RequiresPermission(resource = "TestResource", scope = "unassigned")
        String unassigned(@PathVariable Long id) {
            return "unassigned:" + id;
        }

        @GetMapping("/resources-unknown-resource/{id}")
        @RequiresPermission(resource = "UnknownResource", scope = "read")
        String unknownResource(@PathVariable Long id) {
            return "unknown-resource:" + id;
        }

        @GetMapping("/resources-unknown-scope/{id}")
        @RequiresPermission(resource = "TestResource", scope = "unknown-scope")
        String unknownScope(@PathVariable Long id) {
            return "unknown-scope:" + id;
        }
    }

    /**
     * Resolves a business-shaped context for the permission check ({@code
     * tenant}) from the resource id - exactly the way a real application's
     * own {@code PermissionContextProvider} would (a real one would look the
     * tenant up from a database; this one uses a fixed, deterministic
     * mapping since there is no database here) - proving the real
     * context-passing wiring works end-to-end against a real Keycloak UMA
     * endpoint and that its decision genuinely depends on the value sent.
     */
    @Component
    static class TenantContextProvider implements PermissionContextProvider {

        static final long TENANT_A_RESOURCE_ID = 1L;
        static final long TENANT_B_RESOURCE_ID = 2L;

        @Override
        public Map<String, String> resolve(Object resourceId) {
            long id = ((Number) resourceId).longValue();
            String tenant = id == TENANT_B_RESOURCE_ID ? "TENANT_B" : "TENANT_A";
            return Map.of("tenant", tenant);
        }
    }

    public static void main(String[] args) {
        org.springframework.boot.SpringApplication.run(ResourceServerHarnessApplication.class, args);
    }
}
