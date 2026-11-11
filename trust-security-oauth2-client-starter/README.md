# trust-security-oauth2-client-starter

A Spring Boot starter that turns a servlet application into a fully
configured OAuth2/OIDC **client with a browser-facing login session** - the
BFF (Backend For Frontend) pattern: the application logs the user in against
one or more identity providers, keeps the resulting token server-side in the
HTTP session, and only ever gives the browser a session cookie. This is
Trust's counterpart to
[`trust-security-resource-server-starter`](../trust-security-resource-server-starter)
(validating a Bearer token an API *receives*) and
[`trust-rest-client-starter`](../trust-rest-client-starter) (relaying that
session's token to calls the application makes *as* that user).

Add the dependency, declare your OAuth2 client registration(s) with Spring
Boot's own native properties, and you get a working, opinionated login/logout
flow - no `HttpSecurity` code to write.

## What it gives every application, with zero extra code

- A complete `SecurityFilterChain`: CORS, CSRF (cookie-based, readable by
  JavaScript), every request authenticated except declared public paths and
  `/actuator/health`.
- `oauth2Login()` fully wired: standard authorization/callback endpoints,
  local logout, RP-initiated OIDC logout, and OIDC back-channel logout.
- Authorities composed from the OIDC user's native claims (`OIDC_USER`,
  scopes, ...) **and** any claim-to-authority mapping you declare - one never
  replaces the other.
- Step-up (re-)authentication (`@RequiresAcr`) with a ready-to-use endpoint
  and return-to-origin flow.
- The authenticated subject in the logging MDC for the duration of each
  request, and the security + request context propagated to `@Async`
  methods.
- Optional resolution of which `ClientRegistration` to use for a login
  request that does not itself name one - a tenant-specific host or path
  (see [Multi-tenant login routing](#multi-tenant-login-routing)).

## Minimal setup

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-security-oauth2-client-starter</artifactId>
</dependency>
```

No version: it comes from the `trust-dependencies` BOM (see the
[repository README](../README.md#use-it-in-an-application)).

```yaml
trust:
  security:
    post-logout-redirect-uri: http://localhost:5173/
spring:
  security:
    oauth2:
      client:
        registration:
          keycloak:
            provider: keycloak
            client-id: bff-app
            client-secret: ${CLIENT_SECRET}
            authorization-grant-type: authorization_code
            scope: openid, profile, email
        provider:
          keycloak:
            issuer-uri: https://keycloak.example.com/realms/my-realm
```

That's it: `GET /oauth2/authorization/keycloak` starts the login flow,
`/login/oauth2/code/keycloak` handles the callback, and every other request
requires an authenticated session. `trust.security.post-logout-redirect-uri`
is the only property this starter itself requires - everything else
(client id/secret, issuer, scopes) is Spring Boot's own native OAuth2 client
configuration, never duplicated by Trust.

## Login and logout, entirely native

- **Login**: `GET /oauth2/authorization/{registrationId}` (Spring Security's
  own standard endpoint, unchanged) - if the application has exactly one
  registration, link to it directly; with several, either link to each
  explicitly or see [Multi-tenant login routing](#multi-tenant-login-routing)
  below.
- **Callback**: `/login/oauth2/code/{registrationId}` - entirely Spring's
  own, matching each registration's `redirect-uri` (defaults to
  `{baseUrl}/login/oauth2/code/{registrationId}`, which already adapts to
  whatever host/port the request actually arrived on).
- **Post-login landing page**: if the browser was denied access to a specific
  protected URL before authenticating, it lands back there, unchanged. If
  login was triggered directly (a bare link to
  `/oauth2/authorization/{registrationId}`, nothing to replay), it lands on
  `trust.security.post-login-redirect-uri` when configured, or this
  application's own root (`/`) otherwise - Spring's native default. A BFF whose root
  isn't a real page (a pure API, its UI served by a separate SPA) should set
  this to the SPA's origin, the same way it already sets
  `post-logout-redirect-uri`.
- **What counts as "nothing to replay"**: only requests that are actually
  navigations. A single-page application typically probes its own session
  state on load with a same-origin `fetch()` (e.g. `GET /api/me`, to decide
  whether to show a login button) - Spring Security's own default would save
  *that* probe as the page to return to, showing its raw JSON response
  instead of the SPA after login. This starter installs a `RequestCache`
  (`NavigationRequestMatcher`) that only saves requests carrying
  `Sec-Fetch-Mode: navigate` (or no such header at all, for non-browser
  clients) - a signal set by the browser itself, never by application script.
  A real protected-page navigation is still saved and replayed; a session
  probe never is. Back off by supplying your own
  `RequestCache` bean (e.g. `NullRequestCache`, to disable saved-request
  replay entirely).
- **Logout**: `POST` to `trust.security.logout-path` (default `/logout`)
  invalidates the local session, deletes the `JSESSIONID` cookie, then
  redirects the browser through the identity provider's own RP-initiated
  logout endpoint (OIDC `end_session_endpoint`), finally landing on
  `trust.security.post-logout-redirect-uri`.
- **Back-channel logout**: `/logout/connect/back-channel/**` is wired and
  public - an identity provider that supports OIDC back-channel logout can
  terminate this application's session out-of-band (e.g. an admin forcing a
  user's session to end), without needing the user's own browser to be
  involved.
- **`invalid_grant` handling** (`OAuth2AuthorizationExceptionHandler`): if a
  refresh token has expired or been revoked at the provider, the resulting
  `OAuth2AuthorizationException` triggers a clean local logout instead of a
  generic `500` - any other authorization error code is left to propagate
  normally.

## Step-up authentication: `@RequiresAcr`

Requires the current session's `acr` claim to equal a specific value,
independent of whatever else the session already grants - exactly the same
annotation as the resource-server starter, wired here for method security on
this BFF's own endpoints:

```java
@RequiresAcr("strong")
@PostMapping("/account/close")
public String closeAccount(...) { ... }
```

A caller whose session doesn't carry the required `acr` gets the same
RFC 9470 challenge as from a resource server (`AcrStepUpAccessDeniedHandler`):
`401` with `WWW-Authenticate: Bearer error="insufficient_user_authentication",
acr_values="strong"` and a Problem Details body. The page reacts by sending
the browser to this starter's step-up endpoint:

```
GET /oauth2/step-up?acr=strong&returnTo=/account/close
```

- `acr` is forwarded as the standard OIDC `acr_values` authorization
  parameter to the identity provider (via `AcrOAuth2AuthorizationRequestResolver`,
  the `OAuth2AuthorizationRequestResolver` bean this starter installs) -
  nothing provider-specific, `acr_values` is OIDC Core §3.1.2.1.
- `returnTo` must be a local application path (`/...`, never `//...` or an
  absolute URL) - rejected otherwise, so this endpoint can never be turned
  into an open redirect.
- On successful re-authentication, `AcrStepUpAuthenticationSuccessHandler`
  reads the saved `returnTo` from the session and redirects there, instead
  of the default post-login destination - transparent to the calling code,
  no controller changes needed beyond declaring `@RequiresAcr`.

## Multi-tenant login routing

When an application has **more than one** `ClientRegistration` and the
browser does not itself call `/oauth2/authorization/{registrationId}`
directly - a tenant-specific host (`acme.example.com`) or a tenant-specific
login path (`/sso/login/acme`) - this starter can resolve the right
registration for you, then hand off entirely to Spring's own login flow.
**If the browser already calls `/oauth2/authorization/{registrationId}`
directly, none of this is needed** - that URL is always handled by Spring
Security itself, completely unaffected by whether this feature is
configured.

Inactive by default: nothing changes, and no extra bean exists, unless
`trust.security.oauth2-client.login.registration-id-resolution` is
explicitly configured - there is no `enabled` flag, the section's presence
alone activates it.

### By host

```yaml
trust:
  security:
    oauth2-client:
      login:
        registration-id-resolution:
          request-pattern: /sso/login
          source: host
          mappings:
            acme.example.com: keycloak-acme
            globex.example.com: keycloak-globex
```

A `GET /sso/login` request whose `Host` (or, behind a trusted reverse proxy
with Spring Boot's own `server.forward-headers-strategy` enabled, the
forwarded host) is `acme.example.com` redirects to
`/oauth2/authorization/keycloak-acme`.

### By path

```yaml
trust:
  security:
    oauth2-client:
      login:
        registration-id-resolution:
          request-pattern: /sso/login/{tenant}
          source: path
          variable-name: tenant
          mappings:
            acme: keycloak-acme
            globex: keycloak-globex
```

`GET /sso/login/acme` extracts `tenant=acme` from the path (Spring
Security's own `PathPatternRequestMatcher` - no custom path parsing) and
redirects to `/oauth2/authorization/keycloak-acme`.

Each `ClientRegistration` itself stays entirely native
(`spring.security.oauth2.client.registration.*`) - Trust's configuration
here never repeats a secret, client id, issuer, or scope.

### What happens on a request matching the pattern

1. The value is extracted (host, or path variable) and looked up in
   `mappings` by **exact match** - no wildcard, no suffix matching, no
   fallback for an unlisted value.
2. Found → redirect (HTTP 302, not an internal forward) to
   `/oauth2/authorization/{registrationId}`, preserving the original query
   string (so `?acr_values=...` from a step-up flow still reaches
   `AcrOAuth2AuthorizationRequestResolver` unchanged). Spring Security then
   handles everything else - building the authorization request, redirecting
   to the identity provider, the callback, the token exchange, the session -
   none of it re-implemented here.
3. Not found → rejected directly with `404` and an
   [RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) `application/problem+json`
   body (a fixed, generic message - it never reveals which hosts/tenants
   *are* configured), rather than falling through to Spring's own
   auto-generated multi-registration login page, which would be a confusing
   result for what is actually a bad tenant/host, not "please choose how to
   log in".

A request outside `request-pattern` is never touched by this mechanism -
including `/oauth2/authorization/**` itself, which this starter refuses to
let `request-pattern` overlap with in the first place (see below).

### Validated at startup, not at first login

- Every value in `mappings` must name a `registrationId` that actually
  exists under `spring.security.oauth2.client.registration.*` - a typo fails
  the application immediately, with the exact offending mapping named.
- `request-pattern` must not overlap `/oauth2/authorization`,
  `/login/oauth2/code`, `/logout/connect/back-channel`, or this
  application's own `logout-path` - Spring's own endpoints are never
  shadowed.
- `source: path` requires `variable-name`, and `request-pattern` must
  actually contain that `{variable-name}` template segment.
- `source: host` rejects a `variable-name` being set at all (a likely
  copy-paste mistake from path-based configuration).

### Providing your own resolution strategy

```java
public interface TrustRegistrationIdResolver {
    Optional<String> resolve(HttpServletRequest request);
}
```

Declaring a bean of this type - to resolve tenants from a database, for
example - replaces Trust's host/path-based default entirely
(`@ConditionalOnMissingBean`); the same request-matching, redirect, and
rejection behavior around it is unaffected either way.

## Mapping claims to authorities

Native OIDC authorities (`OIDC_USER`, and anything Spring Security itself
already computed from the ID Token/UserInfo response) are always available,
with no configuration. On top of that, map any additional claim to
authorities:

```yaml
trust:
  security:
    authorities:
      mappings:
        - path: realm_access.roles
          prefix: ROLE_
        - path: groups
          prefix: GROUP_
          separator: ","
```

- **Never inspects the access token** - only the claims Spring Security
  already resolved for the logged-in user (ID Token merged with the
  UserInfo response, ID Token taking precedence on a conflicting key - Spring
  Security's own merge order, not a Trust rule). OAuth2/OIDC never
  guarantees the access token is a locally decodable JWT, so it is never
  parsed here.
- **No `{clientId}` placeholder support** here, unlike the resource-server
  starter's equivalent mechanism: a BFF may hold several registrations at
  once, so there is no single "this application's own client id" to
  substitute. A path such as `resource_access.{clientId}.roles`, copied from
  a resource-server config, will never match anything in this starter - name
  the concrete client id directly instead (e.g. `resource_access.bff-app.roles`).
- `separator` only matters for a single-string claim value - a claim that is
  already a JSON array is used as-is.
- No mapping configured at all means only the native OIDC authorities apply
  - never an error.

Declaring your own `GrantedAuthoritiesMapper` bean replaces this whole
mechanism entirely - an all-or-nothing override, like every other bean in
this starter.

## Reading the current user without `SecurityContextHolder`

Two beans, auto-configured and injectable anywhere, spare application code
from reaching into `SecurityContextHolder`/`Authentication` casts directly -
identical contract to the resource-server starter:

```java
public record AuthenticatedUser(String subject, String username, String email) {}

public interface CurrentUserProvider {
    Optional<AuthenticatedUser> getCurrentUser();
}

public interface CurrentAuthoritiesProvider {
    Set<String> getAuthorities();
}
```

`AuthenticatedUser` is populated from `sub`/`preferred_username`/`email`;
`getCurrentUser()` returns `Optional.empty()` when there is no authenticated
session. Both `@ConditionalOnMissingBean` - declare your own to source the
current user differently without touching call sites.

## Security headers: Content-Security-Policy

Off by default - this starter never sends a CSP header on its own unless
explicitly enabled, since the right policy is application-specific:

```yaml
trust:
  security:
    oauth2-client:
      headers:
        content-security-policy:
          enabled: true
          policy: "default-src 'self'; frame-ancestors 'none'; base-uri 'self'; object-src 'none'"
```

The value shown above is also the default `policy` once `enabled: true` is
set.

## CORS

```yaml
trust:
  security:
    allowed-origins:
      - https://app.example.com
```

- Must include the scheme (`https://...`, not just the host) - validated at
  startup.
- **No origin configured means no cross-origin call is allowed** - not a
  permissive wildcard default.
- Credentials (cookies) are always allowed for whatever origins are
  configured; `GET`/`POST`/`PUT`/`DELETE`/`PATCH`/`OPTIONS` and any header
  are permitted.

## Errors: Problem Details

Every authentication/authorization failure on this starter's own
`SecurityFilterChain` - including the `@RequiresAcr` step-up case and the
multi-tenant login rejection above - is written as an
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) `application/problem+json`
body. Nothing extra to configure for this - it's part of the filter chain
this starter installs.

## Public paths

`/actuator/health` and `/logout/connect/back-channel/**` are always public.
The multi-tenant login `request-pattern`, when configured, is added
automatically - never declare it again under `public-paths`. Add any other
application-specific public endpoint:

```yaml
trust:
  security:
    public-paths:
      - /public/status
```

Every other path requires an authenticated session.

## Cross-cutting behavior

- **Correlation ID**: shared with `trust-rest-client-starter` and the
  resource-server starter via `trust-web-core` - the same correlation
  identifier flows through logs and into any outbound call this BFF itself
  makes as a client.
- **Authenticated subject in logs**: the session's `sub` claim is placed in
  the logging MDC for the duration of each request, then cleared.
- **`@Async` propagation**: the security context and request context are
  copied onto any `@Async`-executed task, so a background continuation of a
  request still sees the caller's authentication and current session -
  needed in particular for session-backed token stores, which resolve the
  access token through the HTTP session rather than the security context
  alone.

## Running alongside `trust-security-resource-server-starter` (multiple `SecurityFilterChain`)

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
        request-pattern: /app/**    # this starter's own scope
    resource-server:
      multi-chain:
        request-pattern: /api/**    # the sibling starter's scope
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
- An application that genuinely needs the two roles to share the *same*
  URL space (not just the same process) is still out of scope - this mode
  only ever means two disjoint chains in one process, never one chain doing
  both jobs on the same request.

## Configuration reference

| Property | Type | Default | Notes |
|---|---|---|---|
| `trust.security.post-logout-redirect-uri` | `String` | *(required)* | Where the browser lands after RP-initiated logout completes. |
| `trust.security.post-login-redirect-uri` | `String` | *(none - falls back to `/`)* | Where the browser lands after a login with no saved request to replay. Never overrides a saved request. |
| `trust.security.logout-path` | `String` | `/logout` | Local endpoint that starts the logout flow. |
| `trust.security.allowed-origins` | `List<String>` | `[]` | CORS origins, each must include the scheme. |
| `trust.security.public-paths` | `List<String>` | `[]` | Added to `/actuator/health` and back-channel logout, always public. |
| `trust.security.oauth2-client.multi-chain.request-pattern` | `String` | *(none - single-chain mode)* | This starter's own URL scope when running alongside `trust-security-resource-server-starter`. See [Multiple SecurityFilterChain](#running-alongside-trust-security-resource-server-starter-multiple-securityfilterchain). |
| `trust.security.oauth2-client.headers.content-security-policy.enabled` | `boolean` | `false` | Emit a CSP header. |
| `trust.security.oauth2-client.headers.content-security-policy.policy` | `String` | restrictive baseline | CSP directives when enabled. |
| `trust.security.oauth2-client.login.registration-id-resolution.request-pattern` | `String` | *(required once configured)* | The login path this mechanism reacts to. |
| `trust.security.oauth2-client.login.registration-id-resolution.source` | `host`\|`path` | *(required once configured)* | Where the discriminating value comes from. |
| `trust.security.oauth2-client.login.registration-id-resolution.variable-name` | `String` | — | Path template variable name; only for `source: path`. |
| `trust.security.oauth2-client.login.registration-id-resolution.mappings` | `Map<String,String>` | *(required once configured)* | Closed allowlist: host/tenant value → `registrationId`. |
| `trust.security.authorities.mappings[].path` | `String` | — | Dot-separated claim path (no `{clientId}` substitution here). |
| `trust.security.authorities.mappings[].prefix` | `String` | — | Prefix applied to every authority found at `path`. |
| `trust.security.authorities.mappings[].separator` | `String` | *(none)* | Splits a single-string claim value into several authorities. |

All of the above ships with IDE autocompletion, type information, and
defaults via `META-INF/spring-configuration-metadata.json`.

## Prerequisites

- `spring-boot-starter-security-oauth2-client` and
  `spring-boot-starter-webmvc` (servlet stack only - no reactive/WebFlux
  support).
- At least one `spring.security.oauth2.client.registration.*` entry.
- For multi-tenant login routing, at least two registrations and the
  `registration-id-resolution` section above.

## What this starter does not do

- **No `client_credentials`/machine-to-machine calls** - this starter is
  exclusively the browser-redirect login pattern; see
  [`trust-rest-client-starter`](../trust-rest-client-starter) for autonomous
  outbound calls.
- **No tenant propagation or data isolation** - multi-tenant login routing
  above only selects which `ClientRegistration` authenticates the browser;
  it never forwards a tenant identifier to downstream APIs, never isolates
  business data, and never verifies that the authenticated user actually
  belongs to the expected tenant.
- **No dynamic `ClientRegistration`** - registrations, and the login
  routing `mappings` above, are static configuration loaded at startup,
  never modified while running.
- **No WebFlux/reactive support** - servlet only.

These are documented boundaries, not oversights.
