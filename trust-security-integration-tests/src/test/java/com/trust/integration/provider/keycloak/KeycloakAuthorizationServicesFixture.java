package com.trust.integration.provider.keycloak;

import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.resource.AuthorizationResource;
import org.keycloak.representations.idm.ClientRepresentation;
import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.representations.idm.authorization.PolicyRepresentation;
import org.keycloak.representations.idm.authorization.ResourceRepresentation;
import org.keycloak.representations.idm.authorization.RolePolicyRepresentation;
import org.keycloak.representations.idm.authorization.ScopePermissionRepresentation;

import java.util.Set;

/**
 * Provisions the minimal Keycloak Authorization Services (UMA) configuration
 * the certification suite needs: one resource with three scopes, a
 * role-based policy, a context-aware Script Policy (the "Deployed Scripts"
 * SPI - see {@code src/test/resources/keycloak/policy-provider}, not the
 * removed "upload JS via Admin API" feature), and permissions tying them
 * together - deliberately leaving one scope ({@value #SCOPE_UNASSIGNED})
 * without any permission, and one resource/scope combination entirely
 * unregistered, so the "unknown resource/scope/no permission" contract tests
 * exercise a real, un-doctored Keycloak response.
 * <p>
 * Done through the Keycloak Admin Client after the container starts, rather
 * than embedded in the realm import JSON: a role policy's wire
 * representation is version-sensitive about how a role reference resolves
 * during import, and a deployed script only registers as a policy *provider
 * type* once the container has actually built with it - neither can be
 * expressed reliably as static realm-import JSON. The realm JSON stays the
 * simple, declarative part (realm/roles/users/clients); this provider-specific
 * piece is isolated here.
 */
final class KeycloakAuthorizationServicesFixture {

    static final String SCOPE_UNASSIGNED = "unassigned";
    private static final String STANDARD_ROLE_POLICY_NAME = "Standard User Role Policy";
    private static final String TENANT_CONTEXT_POLICY_NAME = "Tenant Context Policy";
    private static final String TENANT_CONTEXT_POLICY_TYPE = "script-tenant-context-policy.js";
    private static final String READ_PERMISSION_NAME = "Read Permission";
    private static final String WRITE_PERMISSION_NAME = "Write Permission";

    private KeycloakAuthorizationServicesFixture() {
    }

    static void provisionAuthorizationServices(String realm) {
        Keycloak admin = KeycloakTestEnvironment.adminClient();

        String clientUuid = admin.realm(realm)
                .clients()
                .findByClientId(KeycloakTestEnvironment.AUTHORIZATION_CLIENT_ID)
                .stream()
                .findFirst()
                .map(ClientRepresentation::getId)
                .orElseThrow(() -> new IllegalStateException(
                        "Client '" + KeycloakTestEnvironment.AUTHORIZATION_CLIENT_ID
                                + "' not found - check the realm import"));

        AuthorizationResource authorization = admin.realm(realm)
                .clients()
                .get(clientUuid)
                .authorization();

        ResourceRepresentation resource = new ResourceRepresentation();
        resource.setName(KeycloakTestEnvironment.AUTHORIZATION_RESOURCE_NAME);
        resource.setDisplayName(KeycloakTestEnvironment.AUTHORIZATION_RESOURCE_NAME);
        resource.addScope(KeycloakTestEnvironment.SCOPE_READ, KeycloakTestEnvironment.SCOPE_WRITE, SCOPE_UNASSIGNED);
        authorization.resources().create(resource).close();

        RolePolicyRepresentation rolePolicy = new RolePolicyRepresentation();
        rolePolicy.setName(STANDARD_ROLE_POLICY_NAME);
        rolePolicy.setLogic(Logic.POSITIVE);
        rolePolicy.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        rolePolicy.addRole(KeycloakTestEnvironment.STANDARD_ROLE, false);
        authorization.policies().role().create(rolePolicy).close();

        // Registers a *reference* to the already-deployed script - the script
        // itself (its "code") is fixed at container-build time, not here.
        PolicyRepresentation tenantContextPolicy = new PolicyRepresentation();
        tenantContextPolicy.setName(TENANT_CONTEXT_POLICY_NAME);
        tenantContextPolicy.setType(TENANT_CONTEXT_POLICY_TYPE);
        tenantContextPolicy.setLogic(Logic.POSITIVE);
        authorization.policies().create(tenantContextPolicy).close();

        ScopePermissionRepresentation readPermission = new ScopePermissionRepresentation();
        readPermission.setName(READ_PERMISSION_NAME);
        readPermission.setLogic(Logic.POSITIVE);
        readPermission.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        readPermission.setResources(Set.of(KeycloakTestEnvironment.AUTHORIZATION_RESOURCE_NAME));
        readPermission.setScopes(Set.of(KeycloakTestEnvironment.SCOPE_READ));
        readPermission.setPolicies(Set.of(STANDARD_ROLE_POLICY_NAME));
        authorization.permissions().scope().create(readPermission).close();

        ScopePermissionRepresentation writePermission = new ScopePermissionRepresentation();
        writePermission.setName(WRITE_PERMISSION_NAME);
        writePermission.setLogic(Logic.POSITIVE);
        writePermission.setDecisionStrategy(DecisionStrategy.UNANIMOUS);
        writePermission.setResources(Set.of(KeycloakTestEnvironment.AUTHORIZATION_RESOURCE_NAME));
        writePermission.setScopes(Set.of(KeycloakTestEnvironment.SCOPE_WRITE));
        writePermission.setPolicies(Set.of(TENANT_CONTEXT_POLICY_NAME));
        authorization.permissions().scope().create(writePermission).close();

        // SCOPE_UNASSIGNED deliberately gets no permission at all.

        KeycloakClientScopeConfigurer.provisionAudienceScopesAndAssignToBff(realm);
    }
}
