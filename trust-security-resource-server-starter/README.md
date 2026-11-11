# trust-security-resource-server-starter

A Spring Boot starter that turns a servlet application into a fully
configured OAuth2 **resource server** - Trust's counterpart to
[`trust-rest-client-starter`](../trust-rest-client-starter) (outbound calls)
and `trust-security-oauth2-client-starter` (browser login / BFF): where
those secure requests an application *sends* or a user's *browser session*,
this starter secures requests an API *receives*, validating the Bearer
token on every call and rejecting anything it can't verify.

Add the dependency, tell it which token format your identity provider
issues and what your application's identity is, and you get a working,
opinionated Bearer resource server - no `HttpSecurity` code to write.

## What it gives every application, with zero extra code

- A complete `SecurityFilterChain`: CSRF disabled, sessions stateless,
  every request authenticated except declared public paths and
  `/actuator/health`.
- Bearer token validation, in whichever format your identity provider uses
  (see [Choosing a token format](#choosing-a-token-format)).
- Authorities composed from the token's native OAuth2 scopes **and** any
  claim-to-authority mapping you declare - one never replaces the other.
- [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) Problem Details on
  every authentication/authorization failure, with the correct
  `WWW-Authenticate` header.
- The authenticated subject in the logging MDC for the duration of each
  request, and the security + request context propagated to `@Async`
  methods.
- Two ready-to-use method-security mechanisms - `@RequiresAcr` (step-up
  authentication) and `@RequiresPermission` (externalized authorization) -
  see [Method security](#method-security).

## Minimal setup

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-security-resource-server-starter</artifactId>
</dependency>
```

No version: it comes from the `trust-dependencies` BOM (see the
[repository README](../README.md#use-it-in-an-application)).

```yaml
trust:
  security:
    resource-server:
      client-id: sample-api        # this application's own OAuth2 client id
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://keycloak.example.com/realms/my-realm
```

That's it: any request without a valid Bearer token gets `401`; a valid one
is authenticated, its scopes become `SCOPE_*` authorities, and
`@PreAuthorize`/method security is active.

`trust.security.resource-server.client-id` is **always required**,
regardless of token format: it's both the audience this API expects inside
a token (see below) and the value substituted for the `{clientId}`
placeholder in claim mappings.

## Choosing a token format

A resource server validates a token exactly **one** way. Pick one of the
three below by configuration alone - never by writing `HttpSecurity` code -
and the starter fails fast at startup if the configuration is ambiguous
(see [If none, or more than one, is configured](#if-none-or-more-than-one-is-configured)).

### JWT / JWKS, single issuer

The common case: one identity provider, one realm/tenant.

```yaml
trust:
  security:
    resource-server:
      client-id: sample-api
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://keycloak.example.com/realms/my-realm
```

The decoder is built from the issuer's own OIDC discovery document
(`${issuer-uri}/.well-known/openid-configuration`), fetched when the
first token arrives rather than at startup (an unreachable issuer does not
prevent the application from starting) - any OIDC-compliant
authorization server works, not just Keycloak. On top of the standard
signature/`exp`/`nbf`/issuer checks, this starter adds one more: the
token's `aud` claim must contain `client-id` - without it, this API would
accept a token issued for any client in the realm, not just for itself.

### JWT, multiple trusted issuers

An API that must accept tokens from more than one trusted authority - two
Keycloak realms, or an internal realm plus a partner's identity provider -
declares an explicit, static allowlist instead of a single `issuer-uri`:

```yaml
trust:
  security:
    resource-server:
      client-id: sample-api
      issuers:
        - issuer-uri: https://keycloak.example.com/realms/internal
        - issuer-uri: https://partner-idp.example.com/realms/partner
          audience: sample-api-partner   # optional, defaults to client-id
          jwk-set-uri: https://partner-idp.example.com/realms/partner/protocol/openid-connect/certs  # optional
```

- Each entry needs only `issuer-uri`. `audience` overrides the expected
  `aud` for that issuer only (defaults to `client-id`, the same rule as
  single-issuer mode). `jwk-set-uri` skips OIDC discovery for that issuer's
  key source only - it never skips issuer validation.
- The token's own `iss` claim (read **before** signature verification,
  purely to pick which issuer's keys/rules to apply) is matched against
  this list by **exact string equality** - no wildcard, no suffix
  matching, no trailing-slash normalization, no discovery of new issuers at
  runtime. A token from an issuer not on the list is rejected with the same
  `401` an actually-invalid token would get, and **without any network
  call**.
- Each issuer's decoder, key fetch, and authorities mapping are built the
  first time a token from that issuer actually arrives - not at startup -
  and then reused. Two issuers are never mixed up even if their key sets
  happen to share a key id.
- List at least two entries to actually use this mode; a single entry is
  functionally equivalent to (and simpler as) single-issuer mode above.

Mutually exclusive with `spring.security.oauth2.resourceserver.jwt.issuer-uri`
and the opaque-token properties below - configuring `issuers` alongside
either fails startup explicitly.

### Opaque token (RFC 7662 introspection)

For an identity provider that issues opaque tokens instead of JWTs -
validated by calling back to the authorization server rather than
verifying a signature locally:

```yaml
trust:
  security:
    resource-server:
      client-id: sample-api
spring:
  security:
    oauth2:
      resourceserver:
        opaquetoken:
          introspection-uri: https://keycloak.example.com/realms/my-realm/protocol/openid-connect/token/introspect
          client-secret: ${INTROSPECTION_CLIENT_SECRET}
          # client-id: optional, see below
```

Two `client-id`-shaped properties exist here and answer different
questions:

| Property | Answers |
|---|---|
| `trust.security.resource-server.client-id` | The audience this API expects **inside** a token - unrelated to introspection. |
| `spring.security.oauth2.resourceserver.opaquetoken.client-id` | The identity this API authenticates **as**, when calling the introspection endpoint itself. |

When the native `opaquetoken.client-id` is left unset, it falls back to
`trust.security.resource-server.client-id` - the common case where a
resource server introspects using its own identity. Set it explicitly only
when introspection genuinely needs a different identity (e.g. a shared
introspection service account).

Authorities are extracted the same way as JWT mode: the introspection
response's attributes go through the exact same claim-mapping mechanism
(see [Mapping claims to authorities](#mapping-claims-to-authorities)) - no
separate configuration to learn.

### If none, or more than one, is configured

| Configuration present | Result |
|---|---|
| `jwt.issuer-uri` only | JWT, single issuer |
| `issuers` (non-empty) only | JWT, multiple issuers |
| `opaquetoken.introspection-uri` only | Opaque token |
| None of the above, and no `JwtDecoder`/`OpaqueTokenIntrospector`/`AuthenticationManagerResolver` bean supplied | **Fails at startup** - this API cannot validate anything |
| `jwt.issuer-uri` **and** `opaquetoken.introspection-uri` | **Fails at startup** - ambiguous, would depend on bean registration order |
| `issuers` **and** `jwt.issuer-uri` or `opaquetoken.introspection-uri` | **Fails at startup** - same reason |

Every failure names exactly which properties/beans are in conflict - never
a silent fallback to Spring Boot's own default `SecurityFilterChain`
(HTTP Basic/form login), and never a coin-flip between two competing
filter chains.

### Supplying your own decoder, introspector, or resolver

Every bean above is `@ConditionalOnMissingBean` - declare your own to take
over that piece entirely:

```java
@Bean
JwtDecoder jwtDecoder() {
    return NimbusJwtDecoder.withJwkSetUri("https://idp.example.com/certs").build();
}
```

```java
@Bean
OpaqueTokenIntrospector opaqueTokenIntrospector() {
    return SpringOpaqueTokenIntrospector.withIntrospectionUri("https://idp.example.com/introspect")
            .clientId("sample-api").clientSecret("secret").build();
}
```

A custom `AuthenticationManagerResolver<HttpServletRequest>` bean similarly
takes over the multi-issuer path entirely - useful when an application
needs routing logic this starter's static allowlist doesn't cover.
Supplying a full `SecurityFilterChain` bean of your own bypasses all of the
above, and this starter's own chain is never created.

## Mapping claims to authorities

Native OAuth2 scopes (`SCOPE_*`, from the token's `scope`/`scp` claim) are
always available as authorities, with no configuration. On top of that, map
any additional claim your identity provider exposes - realm roles, client
roles, custom permission claims - to authorities:

```yaml
trust:
  security:
    authorities:
      mappings:
        - path: realm_access.roles
          prefix: ROLE_
        - path: resource_access.{clientId}.roles
          prefix: ROLE_
        - path: permissions.scopes
          prefix: PERM_
          separator: ","
```

- `path` navigates nested claims with `.`; a segment written `{clientId}`
  is substituted with `trust.security.resource-server.client-id` -
  convenient for Keycloak's per-client role claim shape, but nothing here
  is Keycloak-specific: any provider's claim structure works the same way.
- `prefix` is applied to every value found at that path.
- `separator` only matters when the resolved value is a single string
  (e.g. `"user,admin"`) - set it to split that string into several
  authorities. A claim that is already a JSON array is used as-is,
  regardless of `separator`.
- No mapping configured at all means no business authority beyond native
  scopes - never an error, since an application using only scope-based
  authorization has nothing to declare here.

Declaring your own `Converter<Jwt, Collection<GrantedAuthority>>` bean
replaces this whole mechanism (native scopes included) - it's an
all-or-nothing override, same as every other bean in this starter.

## Method security

Both mechanisms below are wired automatically - no `@EnableMethodSecurity`
to add, no interceptor to register.

### Step-up authentication: `@RequiresAcr`

Requires the token's `acr` claim to equal a specific value, independent of
whatever else the token grants:

```java
@RequiresAcr("strong")
@PutMapping("/documents/{id}/attachments")
public void addAttachment(@PathVariable String id, ...) { ... }
```

A caller authenticated with a weaker method gets `401`, not `403` - the
identity is valid, but insufficient for this specific operation - with a
`WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="strong"`
header telling the client exactly what re-authentication is needed, plus
the usual Problem Details body.

### Externalized authorization: `@RequiresPermission`

Delegates a yes/no authorization decision to an external policy decision
point, rather than encoding business rules as `@PreAuthorize` expressions:

```java
@RequiresPermission(resource = "Document", scope = "modify")
@PutMapping("/documents/{id}")
public void updateDocument(@PathVariable String id, ...) { ... }
```

This starter defines the extension point but ships no policy engine of its
own - supply an `AuthorizationDecisionClient` bean matching your identity
provider's authorization backend (e.g.
`trust-security-keycloak-authorization-starter` for Keycloak Authorization
Services/UMA), or implement the interface directly against any PDP (OPA, a
custom service, another IAM).

Behavior without one is explicit, not accidental:

- **No `AuthorizationDecisionClient` bean at all**: every `@RequiresPermission`
  check is refused (never granted), with a one-time `WARN` at startup - an
  application using only `@RequiresAcr`/`@PreAuthorize` is never forced to
  supply an unused dependency, but one that does use `@RequiresPermission`
  fails closed, never open, until a client is provided.
- **More than one `AuthorizationDecisionClient` bean**: fails at startup,
  naming the competing beans - never an arbitrary pick.

#### Implementing `AuthorizationDecisionClient`

The interface is a single method, taking a provider-neutral request and
returning a plain boolean - no vendor vocabulary leaks into application
code:

```java
public interface AuthorizationDecisionClient {
    boolean isAllowed(AuthorizationRequest request);
}

public record AuthorizationRequest(
        Authentication authentication,   // may be null; adapters should deny rather than throw
        String resource,                 // from @RequiresPermission(resource = ...)
        String action,                   // from @RequiresPermission(scope = ...)
        Map<String, String> context) {}  // see below - never null, empty by default
```

```java
@Component
class OpaAuthorizationDecisionClient implements AuthorizationDecisionClient {

    private final RestClient restClient;

    @Override
    public boolean isAllowed(AuthorizationRequest request) {
        return restClient.post()
                .uri("/v1/data/authz/allow")
                .body(Map.of(
                        "input", Map.of(
                                "subject", request.authentication().getName(),
                                "resource", request.resource(),
                                "action", request.action(),
                                "context", request.context())))
                .retrieve()
                .body(OpaResponse.class)
                .result();
    }
}
```

#### Attaching resource context: `@AuthorizationResourceId` / `PermissionContextProvider`

A permission check often needs more than "who" and "what action" - it
needs attributes of the **specific resource** being acted on (its owner,
department, status, ...) so the policy decision point can make an
attribute-based decision (e.g. "a manager can modify a document only in
their own department"). Annotate the method parameter carrying the
resource's identifier with `@AuthorizationResourceId`, naming a
`PermissionContextProvider` bean that resolves that identifier into
context attributes:

```java
@Component
class DocumentPermissionContextProvider implements PermissionContextProvider {

    private final DocumentRepository documents;

    @Override
    public Map<String, String> resolve(Object resourceId) {
        Document document = documents.findById((String) resourceId).orElseThrow();
        return Map.of(
                "ownerId", document.getOwnerId(),
                "department", document.getDepartment());
    }
}
```

```java
@RequiresPermission(resource = "Document", scope = "modify")
@PutMapping("/documents/{id}")
public void updateDocument(
        @AuthorizationResourceId(DocumentPermissionContextProvider.class) @PathVariable String id,
        ...) { ... }
```

The resolved map becomes `AuthorizationRequest.context()` for that call -
your `AuthorizationDecisionClient` reads it however its policy engine
expects. Rules, enforced at each check:

- At most **one** `@AuthorizationResourceId` parameter per method - a
  second one fails the call with `IllegalStateException`.
- The annotated argument's value must not be `null` at call time.
- The named `PermissionContextProvider` is resolved as a Spring bean by
  type (`ApplicationContext.getBean(...)`) - it must exist in the context,
  or the call fails with `IllegalStateException` naming the missing type.
- A method with **no** `@AuthorizationResourceId` parameter simply sends an
  empty context - this mechanism is opt-in per method, not required to use
  `@RequiresPermission` at all.

## Reading the current user without `SecurityContextHolder`

Two beans, auto-configured and injectable anywhere, spare application code
from reaching into `SecurityContextHolder`/`Authentication` casts directly:

```java
public record AuthenticatedUser(String subject, String username, String email) {}

public interface CurrentUserProvider {
    Optional<AuthenticatedUser> getCurrentUser();
}

public interface CurrentAuthoritiesProvider {
    Set<String> getAuthorities();
}
```

```java
@RestController
class ProfileController {

    private final CurrentUserProvider currentUserProvider;

    @GetMapping("/me")
    public AuthenticatedUser me() {
        return currentUserProvider.getCurrentUser()
                .orElseThrow(() -> new IllegalStateException("no authenticated user"));
    }
}
```

- `AuthenticatedUser` is populated from the token's `sub`,
  `preferred_username`, and `email` claims - any of the three may be
  `null` if the identity provider doesn't include it.
- `getCurrentUser()` returns `Optional.empty()` when there is no
  authenticated principal, or when the principal isn't claim-based (e.g. a
  custom `Authentication` an application installed itself) - never throws.
- `getAuthorities()` returns the same authorities method security sees
  (native scopes plus any claim mapping), as plain strings, `Set.of()` when
  unauthenticated.
- Both are `@ConditionalOnMissingBean` - declare your own to source the
  current user differently (e.g. enriched from a database lookup) without
  touching call sites.

## Errors: Problem Details everywhere

Every authentication failure (`401`, including the `@RequiresAcr` step-up
challenge above) and authorization failure (`403`) is written as an
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) `application/problem+json`
body, with the standard OAuth2 Bearer `WWW-Authenticate` header set
correctly for the specific failure (missing token, expired token, invalid
signature, insufficient scope, insufficient ACR, ...). Nothing extra to
configure for this - it's part of the filter chain this starter installs.

## Public paths

`/actuator/health` is always public. Add any application-specific public
endpoint:

```yaml
trust:
  security:
    resource-server:
      public-paths:
        - /public/ping
        - /public/status
```

Every other path requires authentication.

## Cross-cutting behavior

- **Correlation ID**: shared with `trust-rest-client-starter` and the BFF
  starter via `trust-web-core` - the same correlation identifier flows
  through logs and into any outbound call this API itself makes as a
  client.
- **Authenticated subject in logs**: the token's `sub` claim is placed in
  the logging MDC for the duration of each request, then cleared - every
  log line written while handling a request can be attributed to a caller
  without touching application logging code.
- **`@Async` propagation**: the security context and request context are
  copied onto any `@Async`-executed task, so a background continuation of
  a request still sees the caller's authentication and can still relay a
  bearer token onward (via `trust-rest-client-starter`) if it makes calls
  of its own.

## Running alongside `trust-security-oauth2-client-starter` (multiple `SecurityFilterChain`)

An application declaring both starters without further configuration fails
to start with an explicit error, rather than let two `SecurityFilterChain`s
silently compete for the same request - a real, common profile (a monolith
serving both a session-based UI and a Bearer-token API, a microservice with
a small admin UI, an app mid-migration to microservices) is not forced into
two separate deployments just to adopt this starter, though.

This "multiple `SecurityFilterChain`" mode - Spring Security's own term for
several chains coexisting in one application, each scoped to its own
`securityMatcher` - is supported when, and only when, **both** starters
declare a disjoint `multi-chain.request-pattern`, each namespaced under its
own starter so the two are unambiguous side by side in one file:

```yaml
trust:
  security:
    oauth2-client:
      multi-chain:
        request-pattern: /app/**    # the sibling BFF starter's own scope
    resource-server:
      multi-chain:
        request-pattern: /api/**    # this starter's scope
```

- Declaring only one side, or leaving both unconfigured, fails to start
  with the same explicit error.
- Two overlapping patterns (including one being a superset of the other,
  such as `/**` on either side) fail to start with a dedicated error naming
  both patterns - no implicit priority between the two chains is ever
  inferred.
- The two patterns must, between them, cover every path this application
  serves: a request outside both is dispatched with **zero** Spring
  Security filtering at all (native `FilterChainProxy` behavior when no
  chain's `securityMatcher` matches), not denied.

## Configuration reference

| Property | Type | Default | Notes |
|---|---|---|---|
| `trust.security.resource-server.client-id` | `String` | *(required)* | Expected token audience; `{clientId}` placeholder source. |
| `trust.security.resource-server.public-paths` | `List<String>` | `[]` | Added to `/actuator/health`, always public. |
| `trust.security.resource-server.issuers[].issuer-uri` | `String` | *(required per entry)* | Enables multi-issuer mode when the list is non-empty. |
| `trust.security.resource-server.issuers[].audience` | `String` | `client-id` | Per-issuer audience override. |
| `trust.security.resource-server.issuers[].jwk-set-uri` | `String` | *(discovery)* | Skips OIDC discovery for that issuer's key source only. |
| `trust.security.resource-server.multi-chain.request-pattern` | `String` | *(none - single-chain mode)* | This starter's own URL scope when running alongside `trust-security-oauth2-client-starter`. See [Multiple SecurityFilterChain](#running-alongside-trust-security-oauth2-client-starter-multiple-securityfilterchain). |
| `trust.security.authorities.mappings[].path` | `String` | — | Dot-separated claim path, `{clientId}` substitutable. |
| `trust.security.authorities.mappings[].prefix` | `String` | — | Prefix applied to every authority found at `path`. |
| `trust.security.authorities.mappings[].separator` | `String` | *(none)* | Splits a single-string claim value into several authorities. |
| `spring.security.oauth2.resourceserver.jwt.issuer-uri` | `String` | — | Native; single-issuer JWT mode. |
| `spring.security.oauth2.resourceserver.opaquetoken.introspection-uri` | `String` | — | Native; opaque-token mode. |
| `spring.security.oauth2.resourceserver.opaquetoken.client-id` | `String` | `client-id` | Native; identity used to call introspection. |
| `spring.security.oauth2.resourceserver.opaquetoken.client-secret` | `String` | — | Native; credential for introspection. |

All of the above ships with IDE autocompletion, type information, and
defaults via `META-INF/spring-configuration-metadata.json`.

## Prerequisites

- `spring-boot-starter-security-oauth2-resource-server` and
  `spring-boot-starter-webmvc` (servlet stack only - no reactive/WebFlux
  support).
- One token-format configuration from [Choosing a token format](#choosing-a-token-format).
- An `AuthorizationDecisionClient` bean only if using `@RequiresPermission` -
  see [Externalized authorization](#externalized-authorization-requirespermission).

## What this starter does not do

- **No symmetric-key JWT validation** - only OIDC-discoverable/JWKS-based
  issuers; there is no authorization server in a symmetric-key setup for
  Trust to trust automatically.
- **No multi-issuer opaque token** - the multi-issuer mechanism above is
  JWT-only; routing an opaque token to the right introspection endpoint
  would need a different strategy (an opaque token carries no readable
  `iss`).
- **No dynamic issuer list** - `issuers` is a static allowlist loaded at
  startup, never modified while running.
- **No WebFlux/reactive support** - servlet only.
- **No generic relay/gateway behavior** - this starter validates tokens for
  *this* application's own endpoints; it is not a proxy.

These are documented boundaries, not oversights.
