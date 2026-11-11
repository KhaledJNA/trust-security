# trust-security-test

Test support for fine-grained authorization (`@RequiresPermission`) in Trust platform applications.

## Purpose

An application using `@RequiresPermission` (or a business annotation composing it, such as `@CanModifyDocument`) needs, in tests, to control the PERMIT/DENY decision without starting Keycloak, UMA, OPA or any other external PDP.

This module provides exactly that: a test `AuthorizationDecisionClient`, driven by the test itself, plugged in exactly where the application would plug a real provider adapter.

```
@RequiresPermission
    ↓
RequiresPermissionAuthorizationManager   (real, from trust-security-core)
    ↓
PermissionChecker                        (real, provided by the application's starter)
    ↓
AuthorizationDecisionClient              (TestAuthorizationDecisionClient - this module)
    ↓
PERMIT / DENY (driven by the test)
```

Only the PDP boundary is replaced. Everything else - annotation resolution, resource resolution (`@AuthorizationResourceId`), context resolution (`PermissionContextProvider`) - is the application's real code.

## Maven dependency

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-security-test</artifactId>
    <scope>test</scope>
</dependency>
```

No version: it comes from the `trust-dependencies` BOM (see the
[repository README](../README.md#use-it-in-an-application)).

## Minimal example

```java
@SpringBootTest
@Import(TrustAuthorizationTestConfiguration.class)
class DocumentsControllerAuthorizationTest {

    @Autowired
    private TestAuthorizationDecisionClient authorizationDecisions;

    @Autowired
    private DocumentsController controller;

    @Test
    void permit() {
        authorizationDecisions.permit("Document", "modify");
        // call the @CanModifyDocument-annotated method -> no exception
    }

    @Test
    void deny() {
        authorizationDecisions.deny("Document", "modify");
        // call -> AuthorizationDeniedException
    }
}
```

Rules are reset automatically after each test method
(`TestAuthorizationDecisionClientResetListener`, registered through
`META-INF/spring.factories`): no need to call `reset()` in a `@BeforeEach`,
even when the Spring context is cached and shared between test classes.

The bean (`testAuthorizationDecisionClient`) is `@Primary`: it also wins when
the application declares its own `AuthorizationDecisionClient`.

## Realistic example (with context)

```java
authorizationDecisions.permit("Document", "modify",
        context -> "tenant-a".equals(context.get("tenant")));
```

The context passed is the one actually resolved by the application's `PermissionContextProvider` (e.g. `DocumentAuthorizationContextProvider`) - not a value made up by the test.

To inspect what the application actually sent:

```java
authorizationDecisions.lastRequest()
        .map(AuthorizationRequest::context)
        .ifPresent(context -> assertThat(context).containsEntry("tenant", "tenant-a"));
```

## What is actually tested

- Resolution of `@RequiresPermission` (including through a business annotation composing it).
- Resolution of `@AuthorizationResourceId` and of the associated `PermissionContextProvider`.
- The real `RequiresPermissionAuthorizationManager` → application `PermissionChecker` wiring.
- The `Authentication`, `resource`, `action` and `context` actually sent to the PDP.

## What is deliberately bypassed

- Any network call to a real PDP (Keycloak UMA, OPA, ...).
- Any Keycloak, UMA or `realm_access`/`resource_access` concept: this module knows none of them.

## Relationship with the other two modules

- `trust-resource-server-test` handles JWT identity (claims → authorities) - not the permission decision.
- `trust-oauth2-client-test` handles OIDC/BFF session identity (claims → authorities, ACR) - not the permission decision.
- `trust-security-test` is the only one of the three that touches `AuthorizationDecisionClient` / `PERMIT`-`DENY`.
