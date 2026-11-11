# trust-security-core

The provider-neutral heart of the Trust security platform: annotations an
application puts on its code, and the logic behind them. Nothing here
knows Keycloak, an HTTP request or a token format - the starters wire it,
adapters plug a provider in.

| Package | Provides |
|---|---|
| `acr` | `@RequiresAcr`: the authentication level a method needs (step-up) |
| `authorization` | `@RequiresPermission`: fine-grained decisions delegated to a pluggable decision point |
| `role` | `ClaimAuthoritiesMapper`: token claims → Spring Security authorities, by configuration |
| `user` | `CurrentUserProvider`, `CurrentAuthoritiesProvider`, `PrincipalClaims`: who is calling |

## Where it sits

```text
application code: @RequiresAcr, @RequiresPermission, CurrentUserProvider
        │
trust-security-core                    ← this module: annotations, rules, ports
        │ wired by
trust-security-resource-server-starter │ trust-security-oauth2-client-starter
        │ decisions by (adapter)
AuthorizationDecisionClient ← trust-security-keycloak-authorization-starter, or your own
```

Applications do not declare it: the starters bring it. They only use its
annotations and interfaces.

| Feature | resource-server starter | oauth2-client starter |
|---|---|---|
| `@RequiresAcr` | yes | yes |
| `@RequiresPermission` | yes | no |
| Claims → authorities mapping | yes (`trust.security.authorities.mappings`) | yes (same property) |
| `CurrentUserProvider`, `CurrentAuthoritiesProvider` beans | yes | yes |

## `@RequiresAcr` - step-up authentication

```java
@GetMapping("/transfers")
@RequiresAcr("strong")
List<Transfer> transfers() { ... }
```

The caller's `acr` claim must **equal** the value: there is no hierarchy
between levels (`"strong"` does not satisfy `@RequiresAcr("substantial")`).
On a method, it overrides one on the class; it also works as a
meta-annotation. A refusal carries the required level
(`AcrAuthorizationResult`), which `trust-security-web` turns into the RFC
9470 step-up challenge. Works with JWT, OIDC login and opaque-token callers
alike.

## `@RequiresPermission` - fine-grained authorization

```java
@PutMapping("/documents/{id}")
@RequiresPermission(resource = "Document", scope = "write")
Document update(@PathVariable @AuthorizationResourceId(DocumentContext.class) long id) { ... }
```

```java
@Component
class DocumentContext implements PermissionContextProvider {
    public Map<String, String> resolve(Object id) {
        return Map.of("tenant", tenantOf((Long) id));   // sent to the decision point
    }
}
```

What happens on each call:

1. the annotation is found on the method, else on its class (a business
   meta-annotation such as `@CanWriteDocument` works too);
2. if one parameter carries `@AuthorizationResourceId`, its value is handed
   to that `PermissionContextProvider` (a Spring bean) and the returned map
   becomes the decision **context**. The id itself is not sent: only the
   context is. At most one such parameter, never `null`;
3. a provider-neutral `AuthorizationRequest(authentication, resource,
   action = scope, context)` goes to the `AuthorizationDecisionClient`;
4. `true` → the method runs; `false` → `AuthorizationDeniedException`
   (403 with the starters).

Fail-closed by construction: no authentication, no annotation found, or
(with the resource-server starter) **no `AuthorizationDecisionClient` at
all** → denied. In the last case the starter logs a `WARN` at startup.
Two clients at once fail the startup.

### Plugging a decision point

```java
@Bean
AuthorizationDecisionClient myPdp() {
    return request -> callMyPolicyEngine(request.resource(), request.action(), request.context());
}
```

`trust-security-keycloak-authorization-starter` is the ready-made one for
Keycloak Authorization Services. `trust-security-test` provides
`TestAuthorizationDecisionClient` to drive PERMIT/DENY from a test.

## Claims → authorities

`ClaimAuthoritiesMapper` walks paths of nested claims and prefixes what it
finds. The starters bind it to `trust.security.authorities.mappings`:

```yaml
trust:
  security:
    authorities:
      mappings:
        - path: realm_access.roles                 # list → one authority per element
          prefix: ROLE_
        - path: resource_access.{clientId}.roles   # {clientId}: this application's client id
          prefix: ROLE_
        - path: groups                             # "sales,support" → two authorities
          prefix: GROUP_
          separator: ","
```

- a list gives one authority per non-blank string element;
- a single string gives one authority, or one per token if `separator` is
  set (never guessed from the value);
- any other value (number, boolean, object) gives nothing and is logged at
  `DEBUG`;
- `{name}` placeholders are replaced after the path is split, so a client
  id containing dots works.

## Current user

```java
@GetMapping("/me")
Map<String, Object> me(CurrentUserProvider users, CurrentAuthoritiesProvider authorities) {
    AuthenticatedUser user = users.getCurrentUser().orElseThrow();   // sub, preferred_username, email
    return Map.of("user", user.username(), "authorities", authorities.getAuthorities());
}
```

Same code whatever the token format (JWT, OIDC session, opaque
introspection). An anonymous caller has no user and no authorities, not
even `ROLE_ANONYMOUS`. `PrincipalClaims.of(authentication)` gives raw claim
access with the same rules.

## Maven dependency

Only for a library or an adapter built on it (applications get it through
a starter):

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-security-core</artifactId>
</dependency>
```

No version: it comes from the `trust-dependencies` BOM (see the
[repository README](../README.md#use-it-in-an-application)).

Every package is `@NullMarked` (JSpecify) and checked by NullAway at build
time.
