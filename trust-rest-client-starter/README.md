# trust-rest-client-starter

A Spring Boot starter that adds Trust's cross-cutting behavior to
**natively declared** outbound HTTP clients - the Trust platform's
counterpart to `trust-security-resource-server-starter` (inbound) and
`trust-security-oauth2-client-starter` (login): where those secure requests
*coming in*, this starter secures and hardens requests an application
*sends out* to another service.

Clients are declared entirely with Spring's own mechanism -
`@ImportHttpServices` + `@HttpExchange` interfaces, configured under
`spring.http.serviceclient.<group>.*` - this starter contributes no
declaration mechanism of its own. What it adds is what Spring doesn't:
token relay, retry, circuit breaking, unified error mapping, correlation,
and observability, applied automatically to every declared group.

It targets both roles a Trust application can play as a caller:

- a **BFF** relaying the current user's session-held OAuth2 token, or
- a **resource server** relaying the bearer token it received on the current
  request,

so that the downstream service can enforce its own authorization rules
against the real caller identity - never a service-account or synthetic
token invented for the occasion - plus two explicitly declared cases:

- a call made **as the application itself** (`client_credentials`, or any
  other grant), for an endpoint that has nothing to do with relaying a
  user,
- a call made **on behalf of the user with a token exchanged for the
  target** (RFC 8693 token exchange) - the user's identity is kept, but the
  token sent is scoped to that one target instead of being the incoming
  token itself.

## What it gives every declared group, with zero configuration

- **Bearer token relay** - automatic, correct for the calling application's
  role and for each individual call's declared intent (see
  [Token relay](#token-relay-declared-not-deduced) below), with its own
  retry on a transient identity-provider failure, kept independent of the
  downstream client's own retry/circuit breaker.
- **Correlation ID propagation** - the current request's correlation ID
  (from `trust-web-core`) is forwarded as an outgoing header; a call made
  with no incoming request at all (a batch run) still gets one, generated
  on the spot.
- **Retry on transient failures** - a connection-level error or a
  `502`/`503`/`504` response is retried automatically, but only for HTTP
  methods safe to repeat, and never for `POST`/`PATCH`.
- **Circuit breaker** - stops calling a downstream service once it looks
  unhealthy, instead of letting every request keep hitting it.
- **Observability** - every call is recorded as an `http.client.requests`
  Micrometer observation, tagged with the group's name - metrics and
  tracing activate automatically the moment the application has a real
  `ObservationRegistry` bean (typically via Actuator + Micrometer), with no
  code change here either way.
- **Health** - the moment any group's circuit breaker is open,
  `/actuator/health` reports `DOWN` - visible before ever opening a metrics
  dashboard.

Two capabilities are deliberately **not** zero-configuration:

- **Transport** (base URL, timeouts, redirects, mTLS bundle) - entirely
  native, under `spring.http.serviceclient.<group>.*`; this starter does
  not add a Trust-specific alternative for any of it.
- **Mutual TLS (client certificates)** specifically - opt in per group by
  naming a `spring.ssl.bundle.*` bundle under the native transport
  property; see [Mutual TLS](#mutual-tls-presenting-a-client-certificate)
  below.

## Declaring a client

```java
package com.example.portal.client;

import org.springframework.web.service.annotation.GetExchange;

public interface DocumentsClient {

    @GetExchange("/documents")
    String findDocuments();
}
```

```java
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.service.registry.ImportHttpServices;

@SpringBootApplication
@ImportHttpServices(types = DocumentsClient.class, group = "documents")
public class PortalApplication {
    // ...
}
```

- `group` names this client for every Trust capability that needs a name -
  circuit breaker, retry, metrics, per-group configuration. **Convention:
  one interface per group**, so that each client has its own circuit
  breaker and its own metrics. Grouping several
  interfaces together remains possible - `@ImportHttpServices(types = {A.class, B.class}, group = "shared")`
  - but it becomes an explicit choice the application makes, and this
    starter logs a warning at startup naming the group and every interface
    in it, since they then share one circuit breaker and one set of
    metrics.
- Methods are declared using Spring's HTTP Interface annotations
  (`@GetExchange`, `@PostExchange`, `@PutExchange`, `@DeleteExchange`,
  `@PatchExchange`) - entirely Spring's own mechanism, nothing Trust-specific
  about the interface itself.

Nothing beyond `@ImportHttpServices` registers the client - it's a plain
Spring bean the moment Spring processes that annotation. Inject it like any
other:

```java
@RestController
public class PortalController {

    private final DocumentsClient documentsClient;

    public PortalController(DocumentsClient documentsClient) {
        this.documentsClient = documentsClient;
    }

    @GetMapping("/api/my-documents")
    public String documents() {
        return documentsClient.findDocuments();
    }
}
```

## Transport: entirely native

Base URL, timeouts, redirects, cookie handling, and mTLS bundle are
configured under `spring.http.serviceclient.<group>.*` - Spring Boot's own
property namespace (`HttpServiceClientProperties`), not this starter's:

```yaml
spring:
  http:
    serviceclient:
      documents:
        base-url: ${documents-api.url}
        connect-timeout: 2s
        read-timeout: 5s
```

## Token relay: declared, not deduced

The relay mode for a call is **declared per interface or per method**, not
inferred from what happens to be in the application context:

- **Without `@ClientRegistrationId`**: relays the current user's token -
  the incoming bearer token in resource-server mode (a JWT, or an opaque
  token validated by RFC 7662 introspection - both are relayed the same
  way), or the session token of the registration the user authenticated
  with, in BFF mode.
- **With `@ClientRegistrationId("registration-id")`**: a token obtained for
  that registration via Spring Security's native
  `OAuth2AuthorizedClientManager`. What that token represents depends on
  the registration's grant type:
  - `client_credentials` - the application itself, regardless of who (if
    anyone) is logged in - see [Autonomous machine-to-machine calls](#autonomous-machine-to-machine-calls-client_credentials);
  - `urn:ietf:params:oauth:grant-type:token-exchange` - the current user,
    through a new token exchanged for the incoming one - see
    [On behalf of the user: token exchange](#on-behalf-of-the-user-token-exchange-rfc-8693).
- **With `@NoTokenRelay`**: no token at all - see below.

```java
public interface DocumentsClient {

    @GetExchange("/documents")
    String findDocuments();                 // relays the current user

    @GetExchange("/documents/{id}/audit-log")
    @ClientRegistrationId("audit-service")
    String auditLog(@PathVariable String id); // application-authenticated, client_credentials
}
```

Both calls can live on the same interface; the annotation is read per
method (or, applied once at the type level, for every method on that
interface).

### Why this is safe regardless of interceptor order

Two interceptors could, in principle, both want to set the
`Authorization` header for the same call - the resource-server relay and
the native `OAuth2ClientHttpRequestInterceptor`. Neither ever does, by
construction: the resource-server interceptor checks for the same request
attribute `@ClientRegistrationId` populates, and **abstains** the moment
it's present, rather than setting a header that a later interceptor might
overwrite. No security property here depends on interceptor ordering - each
interceptor decides for itself, from information already on the request or
already in the security context, never from what another interceptor did
or didn't do.

### Startup guards

An application fails to start, naming the interface (and method, when
that's where the annotation is) and the registration in question, when:

- an interface or method carries `@ClientRegistrationId("x")` but no
  `OAuth2AuthorizedClientManager` bean is declared in the application -
  a call declared to use a registration cannot be authorized without one;
- `@ClientRegistrationId` names a registration that doesn't exist under
  `spring.security.oauth2.client.registration.<id>` - almost always a typo;
- Trust's default manager is active and `@ClientRegistrationId` names a
  registration whose grant type it doesn't support (anything other than
  `client_credentials` or token exchange);
- a call is annotated both `@NoTokenRelay` and `@ClientRegistrationId` on a
  token-exchange registration - the exchanged token still identifies the
  user, which `@NoTokenRelay` forbids.

### Runtime failure: never a silent fallback to the user's token

A `@ClientRegistrationId`-annotated call never falls back to relaying the
current user's token because its own technical token could not be obtained.
Every failure that can actually happen at request time - the token endpoint
unreachable, an `invalid_client` response, a malformed token response,
`token-acquisition-retry` exhausted - makes the manager throw, and the call
never reaches the target API; see
[Errors are never swallowed](#errors-are-never-swallowed-and-never-fall-back-to-a-users-token)
below for the full list.

The one native Spring Security outcome that isn't a thrown exception is a
registration whose grant type the active manager doesn't support:
`OAuth2AuthorizedClientManager.authorize(...)` then returns `null` instead of
throwing, and the call would go out with **no `Authorization` header** and a
logged warning rather than being blocked. Trust's own default manager can
never hit this path - it only ever handles `client_credentials` and token
exchange, `@ClientRegistrationId` naming a registration of any other grant
type fails at **startup** instead (see [Startup guards](#startup-guards)
above), and a token exchange with no user token to exchange throws
`TokenExchangeSubjectException` rather than returning `null`. It
remains a real possibility only for an application-supplied
`OAuth2AuthorizedClientManager` (see
[Providing your own manager](#providing-your-own-oauth2authorizedclientmanager)),
whose supported grant types Trust has no way of verifying - in that case, a
call declared as application-authenticated either goes out correctly
authenticated, or visibly unauthenticated - never silently mis-authenticated
as someone else.

### Forbidding relay outright: `@NoTokenRelay`

Some downstream calls must never carry the current user's identity - a
public endpoint reached through the same declarative client, or a target
that must not learn who's calling. `@NoTokenRelay` suppresses resource-server
relay (both the JWT and the opaque-token branch) for that call, without
touching anything else about it - `@ClientRegistrationId` on the same or a
different method is unaffected, since that's a separate, application-authenticated
path.

Unlike `@NoRetry`, it can be placed on the **interface** as well as a
method - the need is as often "never for this client" as "never for this
one call":

```java
// forbidden for every method on this client
@NoTokenRelay
public interface PublicCatalogClient {

    @GetExchange("/catalog")
    String listItems();
}

// or just this one call, the rest of the interface unaffected
public interface DocumentsClient {

    @GetExchange("/documents")
    String findDocuments();          // still relays normally

    @GetExchange("/documents/public-summary")
    @NoTokenRelay
    String publicSummary();          // never carries the caller's token
}
```

Scoped deliberately to resource-server relay: it has no effect on the BFF/
`@ClientRegistrationId` path, which declares its own token. One exception: combined with a **token-exchange**
registration, the application fails to start - the exchanged token still
identifies the user, so the two annotations would contradict each other.

## Autonomous machine-to-machine calls: `client_credentials`

Calling an API **as the application itself** - no incoming user, no BFF
session, nothing to relay - needs exactly two things, and nothing else:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          inventory-m2m:
            provider: keycloak
            client-id: document-inventory
            client-secret: ${INVENTORY_CLIENT_SECRET}
            authorization-grant-type: client_credentials
            scope: inventory.read
        provider:
          keycloak:
            issuer-uri: https://keycloak.example.com/realms/my-realm
```

```java
public interface InventoryClient {

    @ClientRegistrationId("inventory-m2m")
    @GetExchange("/inventories/{id}")
    Inventory getInventory(@PathVariable String id);
}
```

That's it - **no `OAuth2AuthorizedClientManager` bean, no `OAuth2AuthorizedClientProvider`,
no interceptor to write**. This starter auto-configures a manager for
exactly this shape (any registration whose grant type is `client_credentials`)
the moment `spring.security.oauth2.client.registration.*` exists and no
manager bean is declared elsewhere - see [Providing your own manager](#providing-your-own-oauth2authorizedclientmanager)
below for when an application needs to take over.

### `registrationId`, `client-id`, `client-secret`, access token - four different things

These are easy to conflate because they all end up near each other in
`application.yml`, but they answer four different questions:

| Name | Answers | Ever sent to the target API? |
|---|---|---|
| `registrationId` (`inventory-m2m` above) | The **local name** this application gave the registration in its own `application.yml` - meaningless outside this app. | No |
| `client-id` (`document-inventory`) | This application's **real identity** as far as Keycloak (or any AS) is concerned. | No |
| `client-secret` | The **credential** proving that identity to Keycloak, at the token endpoint only. | No |
| access token | The **only** thing that ever leaves this application for the target API, as `Authorization: Bearer <token>`. | **Yes** |

### Priority when both token relay and `@ClientRegistrationId` could apply

```
@ClientRegistrationId, client_credentials registration  →  technical token, always
@ClientRegistrationId, token-exchange registration      →  token exchanged for the current user's
No @ClientRegistrationId                                →  relay the current user's token (resource-server or BFF mode)
Neither applies                                         →  no Authorization header, nothing invented
```

This is not a preference order to configure - it follows from how the
interceptors work (`ResourceServerTokenRelayInterceptor` abstains the moment
the annotation's request attribute is present, before it ever looks at the
security context). A call declared `@ClientRegistrationId`
**never** carries the incoming user's token, even if one is present in the
same request - the technical token always wins, deterministically, not as a
fallback. A token-exchange registration sends the user's identity too, but
never the incoming token itself - always the one Keycloak issued in
exchange.

### Works with no user, no session, no request at all

The technical token is cached under a principal derived from the
registration itself (conceptually `trust-client-credentials:inventory-m2m`),
never from `SecurityContextHolder` or the current `HttpServletRequest`. That
means a `@ClientRegistrationId("inventory-m2m")` call behaves identically
whether it is made:

- inside a real incoming request (resource server or BFF),
- from a `@Scheduled` task,
- from a message listener,
- from a plain batch application with `spring.main.web-application-type=none`,
- from any other thread with no `SecurityContext` at all.

Two users hitting the same `@ClientRegistrationId`-annotated endpoint never
cause two separate tokens to be fetched and cached - the cache key is the
registration, not whoever happens to be logged in.

### Errors are never swallowed, and never fall back to a user's token

Every failure that can happen while obtaining the technical token -
unknown `registrationId`, a registration missing `client-id`, a grant type
this starter's default manager doesn't support (see below), the token
endpoint being unreachable, an `invalid_client` response, a malformed token
response - either fails the application at **startup** (an unknown or
grant-type-incompatible registration, named explicitly in the error) or
throws out of the call **before** the target API is ever reached (anything
that can only be known at request time - a token endpoint outage, a bad
response). A `@ClientRegistrationId`-annotated call never silently falls
back to relaying the current user's token because its own token could not
be obtained - it fails loudly instead, exactly like every other startup
guard in this starter.

### Providing your own `OAuth2AuthorizedClientManager`

Trust's default manager only understands `client_credentials` and token
exchange - by design, it doesn't guess at what other grant types an
application might also need. If an application needs `@ClientRegistrationId` to also reach an
`authorization_code` registration, or needs any other customization of how
tokens are obtained, declaring an `OAuth2AuthorizedClientManager` bean of
its own takes over entirely - Trust's default backs off
(`@ConditionalOnMissingBean`) and never contests it:

```java
@Bean
OAuth2AuthorizedClientManager authorizedClientManager(
        ClientRegistrationRepository clientRegistrationRepository,
        OAuth2AuthorizedClientService authorizedClientService) {

    AuthorizedClientServiceOAuth2AuthorizedClientManager manager =
            new AuthorizedClientServiceOAuth2AuthorizedClientManager(
                    clientRegistrationRepository, authorizedClientService);
    manager.setAuthorizedClientProvider(OAuth2AuthorizedClientProviderBuilder.builder()
            .clientCredentials()
            .authorizationCode()
            .build());
    return manager;
}
```

## On behalf of the user: token exchange (RFC 8693)

Relaying the incoming token as-is means that token must be accepted by
every service down the chain - its audience ends up covering all of them,
and if it leaks anywhere it opens every door. Token exchange keeps the
user's identity but sends each target a **token issued for that target
only**:

```
User ──X──▶ APP1 ──X──▶ APP2 ──Y──▶ APP3
                          │
                          └─ X sent to Keycloak as subject_token
                             Y returned: sub = same user, aud = APP3
```

Declared exactly like a `client_credentials` call - only the registration's
grant type differs:

```yaml
spring:
  security:
    oauth2:
      client:
        registration:
          inventory-obo:
            provider: keycloak
            client-id: document-gateway     # APP2's own client, allowed to exchange
            client-secret: ${GATEWAY_CLIENT_SECRET}
            authorization-grant-type: urn:ietf:params:oauth:grant-type:token-exchange
            scope: inventory.read
```

```java
public interface InventoryClient {

    @ClientRegistrationId("inventory-obo")
    @GetExchange("/inventories/{id}")
    Inventory getInventory(@PathVariable String id);  // Y, for the current user
}
```

No manager bean to declare - Trust's default manager handles this grant
type too. What it does:

- **Subject token**: the incoming bearer token of the current request -
  a JWT or an opaque token (RFC 7662), both supported. It is always sent as
  `subject_token_type=urn:ietf:params:oauth:token-type:access_token`,
  which Keycloak's standard token exchange requires (Spring's own default
  would send a JWT as `...:jwt`, and would not find an opaque token at all).
- **Cached per user**: the exchanged token is cached under the user's own
  name (the JWT `sub`) and reused until it expires - never shared between
  users. A `401` from the target (`invalid_token`) evicts it, so the next
  call exchanges again; a `403` does not - exchanging again would not
  change the user's rights.
- **No user, no call**: with no authenticated user (batch, scheduled task,
  listener, anonymous request), or a user authenticated without a bearer
  token (form login, a BFF session), the call throws
  `TokenExchangeSubjectException` **before anything is sent** - it never
  goes out unauthenticated and never falls back to the application's own
  identity. Use a `client_credentials` registration for calls with no user.
- **Exchange refused**: an error from the token endpoint (`invalid_request`,
  `access_denied`, ...) throws, and the target is never called - the
  incoming token is never relayed as a fallback.

On the Keycloak side (standard token exchange, Keycloak 26.2+), the
exchanging client (`document-gateway` above) needs:

- **Client authentication** on, and **Standard Token Exchange** enabled in
  its capability config;
- the target client (APP3) reachable as an **audience** - typically through
  an audience mapper on a client scope assigned to the exchanging client;
- the incoming token X must have the exchanging client in its own audience.

One thing to watch: the default `OAuth2AuthorizedClientService` is
in-memory, and keeps one entry per user and per token-exchange
registration until it is overwritten or evicted.

## Configuration reference

Properties Trust adds beyond the native transport properties above live
under `trust.rest-client`, next to `trust.security.*` used by the other
Trust modules. Every one is optional.

| Property | Type | Default | Scope |
|---|---|---|---|
| `trust.rest-client.retry.enabled` | `boolean` | `true` | Global, overridable per group |
| `trust.rest-client.retry.max-attempts` | `int` | `3` | Global, overridable per group |
| `trust.rest-client.retry.wait-duration` | `Duration` | `200ms` | Global, overridable per group |
| `trust.rest-client.retry.retryable-status-codes` | `Set<Integer>` | `502, 503, 504` | Global, overridable per group |
| `trust.rest-client.circuit-breaker.enabled` | `boolean` | `true` | Global, overridable per group |
| `trust.rest-client.circuit-breaker.failure-rate-threshold` | `float` | `50` (%) | Global, overridable per group |
| `trust.rest-client.circuit-breaker.sliding-window-size` | `int` | `10` | Global, overridable per group |
| `trust.rest-client.circuit-breaker.minimum-number-of-calls` | `int` | `10` | Global, overridable per group |
| `trust.rest-client.circuit-breaker.wait-duration-in-open-state` | `Duration` | `30s` | Global, overridable per group |
| `trust.rest-client.circuit-breaker.permitted-number-of-calls-in-half-open-state` | `int` | `3` | Global, overridable per group |
| `trust.rest-client.token-acquisition-retry.enabled` | `boolean` | `true` | **Global only** |
| `trust.rest-client.token-acquisition-retry.max-attempts` | `int` | `3` | **Global only** |
| `trust.rest-client.token-acquisition-retry.wait-duration` | `Duration` | `200ms` | **Global only** |
| `trust.rest-client.health.enabled` | `boolean` | `true` | **Global only** |

A per-group override replaces only the fields it sets - anything left
unset falls back to the global default:

```yaml
trust:
  rest-client:
    retry:
      max-attempts: 3
      wait-duration: 200ms

    groups:
      documents:                  # matches @ImportHttpServices(group = "documents")
        retry:
          max-attempts: 5
          wait-duration: 300ms
        circuit-breaker:
          failure-rate-threshold: 75
```

All of the above ships with full IDE autocompletion, type information,
defaults and documentation via
`META-INF/spring-configuration-metadata.json` - no need to open this
starter's source to configure it correctly.

## Retry: what is and is not retried, and why

A call is retried only if **both** are true:

1. Its HTTP method is one HTTP itself defines as safe to repeat -
   `GET`, `HEAD`, `OPTIONS`, `PUT`, `DELETE`.
2. It failed with a connection-level error, or a response status in
   `retryable-status-codes`.

`POST`/`PATCH` are never retried, and a `400`/`401`/`403`/`404` is never
retried either (retrying a client-side or authorization error only repeats
the same failure).

If every attempt keeps failing, the **last real response is returned as
received** - it is not swallowed into a synthetic exception, so ordinary
response handling downstream still sees the actual, final outcome.

### Opting a single method out: `@NoRetry`

`PUT`/`DELETE` are idempotent in the HTTP sense - repeating them leaves the
target resource in the same end state - but that does not guarantee every
side effect the endpoint produces is itself safe to duplicate (a
notification, an audit entry, a downstream event). Annotate that one method
with `@NoRetry` to opt it out individually, while every other method on the
same interface keeps the group's normal retry policy:

```java
public interface DocumentsClient {

    @GetExchange("/documents")
    String findDocuments();

    /**
     * Archiving a document also sends a notification. Retrying
     * this call after a lost response could send that notification twice,
     * even though the PUT itself is idempotent - so it opts out.
     */
    @PutExchange("/documents/{id}/archive")
    @NoRetry
    String archiveDocument(@PathVariable String id);
}
```

`findDocuments()` above is still retried normally; only `archiveDocument(...)`
bypasses retry - it still counts toward the circuit breaker, since whether a
call is safe to repeat is a different question from whether it should count
toward the target's observed health.

## Token acquisition: retried, but never through the downstream client's own resilience

Any call presenting a token via `OAuth2AuthorizedClientManager` - a BFF's
own session token, or a `@ClientRegistrationId`-declared application call -
first goes through acquiring/refreshing that token before the request to
the downstream service is even attempted. If the identity provider is
briefly unavailable, that step fails with a `ClientAuthorizationException` -
**not** an `IOException`, so it would not be caught by
`retry.retryable-status-codes` or count as a `5xx` even if it were somehow
routed through the downstream client's own retry/circuit breaker.

This has its own, separate retry (`token-acquisition-retry.*` above),
sharing the same underlying `RetryRegistry` as every group's retry (so it
gets the same `resilience4j.retry.calls` metrics), but registered under its
own name - `oauth2:<registration-id>` - **never** the downstream group's
name, and it never touches that group's circuit breaker at all, isolated
per registration.

This separation is deliberate, not an oversight: a struggling identity
provider is not a signal about `documents`'s own health. Counting a
Keycloak blip against `documents`'s circuit would open it for the wrong
reason, and whoever is looking at `documents`'s dashboard would wrongly
conclude *that API* is unhealthy. `trust.rest-client.token-acquisition-retry`
is global only (not per-group) for the same reason: every call sharing the
same registration shares the same identity provider, and therefore the
same token-acquisition health.

## Circuit breaker: protecting an already-struggling service

Retry protects against a single transient failure; it does nothing to stop
every incoming request from hammering a service that has been down for the
last 30 seconds - each one still tries, and still retries. The circuit
breaker addresses that: once enough calls to a group have failed, it
**opens** - every further call fails immediately with `CallNotPermittedException`,
without even attempting the network call - for `wait-duration-in-open-state`,
after which a limited number of trial calls are let through to test whether
the target has recovered.

A call counts as a failure for the circuit breaker when it throws (a
connection-level `IOException`) or returns a `5xx` response - **not**
configurable per status code the way retry's `retryable-status-codes` is,
and deliberately broader than it: a `500` a real bug would keep producing
is not worth *retrying*, but it is still a real signal the service is
unhealthy, so it still counts here. A `4xx` never counts - it reflects the
caller's request, not the target's health.

Unlike retry, the circuit breaker applies to **every** HTTP method,
including `POST`/`PATCH` and calls annotated `@NoRetry`. When both are
enabled, the circuit breaker wraps retry - so a transient failure that
retry successfully recovers from never counts as a failure; only the
final, post-retry outcome does.

```yaml
trust:
  rest-client:
    groups:
      documents:
        circuit-breaker:
          failure-rate-threshold: 75    # this API is noisier than most - tolerate more before tripping
          wait-duration-in-open-state: 15s
```

## Observability: `http.client.requests`, tagged by group name

Every call made through a declared group is wrapped in a Micrometer
`Observation` - the same `http.client.requests` observation Spring's
`RestClient` already knows how to produce, with one difference: the
`client.name` tag is the group name declared on `@ImportHttpServices`, not
Spring's own default (the request's URI host).

That matters because the host isn't always a stable or unique identifier -
two groups can share a host on different paths, and a URL can change
across environments while the group name stays the same - and because the
group name is already the identifier retry and circuit-breaker metrics for
the same group use, so a dashboard can correlate the three without a
mapping table.

This requires **no configuration and no new dependency to add on this
starter's side**: if the application already exposes a real
`ObservationRegistry` bean (brought in by `spring-boot-starter-actuator`
plus a Micrometer registry such as `micrometer-registry-prometheus`),
metrics and tracing activate automatically. Without one, every observation
is silently a no-op - the starter never requires Actuator itself.

### Activating it and seeing the data

Add to the **consuming application**'s `pom.xml` (not this starter's):

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-actuator</artifactId>
</dependency>
<dependency>
    <groupId>io.micrometer</groupId>
    <artifactId>micrometer-registry-prometheus</artifactId>
</dependency>
```

Actuator's HTTP endpoints are not exposed by default beyond `/health` -
expose at least `metrics` and `prometheus` in the application's own
`application.yml`:

```yaml
management:
  endpoints:
    web:
      exposure:
        include: metrics,prometheus
```

Then, with the application running:

- **Quick lookup, no extra infra** - `GET /actuator/metrics/http.client.requests`
  returns JSON (count, total time, ...); add a tag filter to scope it to one
  group: `GET /actuator/metrics/http.client.requests?tag=client.name:documents`.
- **For a real dashboard/alerting setup** - `GET /actuator/prometheus` returns
  the same data in Prometheus's text exposition format. A Prometheus server
  scrapes that endpoint on an interval, and Grafana queries Prometheus to
  build dashboards and alerts. Without something actually scraping
  `/actuator/prometheus`, the data only ever sits in the application's own
  memory - `/actuator/metrics` is the only way to see it without that
  extra infrastructure.
- **Distributed tracing** additionally needs `micrometer-tracing-bridge-brave`
  (or `-otel`) plus a reporter/exporter (e.g. `zipkin-reporter-brave`), and a
  tracing backend actually running (Zipkin UI, Jaeger, an OTel collector) -
  without one running, there is nowhere for a span to show up even with the
  dependency present.

### Retry and circuit breaker state, as metrics too

Every group's `Retry` and `CircuitBreaker` instance lives in a shared
`RetryRegistry`/`CircuitBreakerRegistry` (both exposed as beans, one per
application, overridable by declaring your own). The moment a real
`MeterRegistry` bean exists, `resilience4j-micrometer` binds both registries
automatically, exposing (among others):

- `resilience4j.circuitbreaker.state` - one gauge per possible state
  (`closed`, `open`, `half_open`, `disabled`, `forced_open`, `metrics_only`),
  tagged by `name` (the same group name used everywhere else) and `state` -
  the active one reads `1`, the rest `0`.
- `resilience4j.circuitbreaker.calls` - call outcomes by `kind`
  (`successful`, `failed`, `ignored`); rejections while the circuit is open
  are counted separately, under `resilience4j.circuitbreaker.not.permitted.calls`.
- `resilience4j.retry.calls` - attempts by `kind`
  (`successful_without_retry`, `successful_with_retry`, `failed_with_retry`,
  `failed_without_retry`).

Same activation story as `http.client.requests` above: no configuration on
this starter's side, and no effect at all if the application has no
`MeterRegistry` bean. Same endpoints too, once the dependencies and
`management.endpoints.web.exposure.include` above are in place - for
example:

```
GET /actuator/metrics/resilience4j.circuitbreaker.state?tag=name:documents
GET /actuator/prometheus   # includes resilience4j.* alongside http.client.requests
```

### Health: an open circuit shows up in `/actuator/health`

Metrics and traces require actively going to look for them. `/actuator/health`
is usually the first thing anyone checks - so the moment any group's
circuit breaker is genuinely `OPEN`, this starter reports the whole
application as `DOWN` there too, with every group's exact state listed:

```json
{
  "status": "DOWN",
  "components": {
    "serviceClientCircuitBreaker": {
      "status": "DOWN",
      "details": {
        "documents": "OPEN",
        "notifications": "CLOSED"
      }
    }
  }
}
```

- Only `OPEN` counts as `DOWN`. `HALF_OPEN` (already attempting recovery)
  and `CLOSED` both report `UP`, but every circuit's exact state is always
  listed in `details` regardless - a transition in progress stays visible
  without flipping the aggregate status.
- Activation is even simpler than metrics/tracing: just
  `spring-boot-starter-actuator` on the classpath (no separate registry
  bean needed) and `management.endpoints.web.exposure.include` covering
  `health` (included by default, unlike `metrics`/`prometheus`). **Without
  Actuator on the classpath at all, this bean is never created, and
  nothing else in this starter is affected either way** - it does not need
  Actuator to start or to function.
- Set `trust.rest-client.health.enabled=false` to opt out explicitly even
  when Actuator is present - the only one of this starter's capabilities
  with its own dedicated disable switch, since unlike metrics/tracing it
  has no natural "nothing is listening" off state of its own.

## Error mapping: `ServiceClientResponseException`

Every non-2xx response - after retries are exhausted, if any applied - is
turned into a `ServiceClientResponseException` (a `RestClientResponseException`),
carrying the downstream service's
[RFC 9457](https://www.rfc-editor.org/rfc/rfc9457) Problem Details payload
when it sent one:

```java
try {
    documentsClient.archiveDocument(id);
} catch (ServiceClientResponseException e) {
    e.getProblemDetail().ifPresentOrElse(
            problem -> log.warn("Documents API rejected the archiving: {}", problem.getDetail()),
            () -> log.warn("Documents API failed with no structured detail: {}", e.getMessage()));
}
```

- `getProblemDetail()` returns `Optional<ProblemDetail>` - empty when the
  response wasn't `application/problem+json`, was empty, or didn't parse as
  valid JSON - never a parsing exception of its own.
- RFC 9457 **extension members** (any field beyond the standard
  `type`/`title`/`status`/`detail`/`instance`) are preserved in
  `problemDetail.getProperties()`, not silently dropped - relies on Spring
  Boot's own `JacksonAutoConfiguration` having registered
  `ProblemDetailJacksonMixin` on the injected `ObjectMapper`, which it does
  automatically whenever `ProblemDetail` is on the classpath - true in any
  Spring Boot application.
- Everything `RestClientResponseException` already offers - `getStatusCode()`,
  `getResponseHeaders()`, `getResponseBodyAsString()` - is still available,
  so existing code catching that type keeps working unchanged.
- One exception type covers both `4xx` and `5xx` uniformly; `getStatusCode()`
  already tells a caller which, when that distinction matters.

## Correlation: a repeatable identifier across every hop

The correlation interceptor propagates the identifier already in the
logging MDC on every outgoing call, exactly as an incoming request's own
`X-Correlation-ID` populated it (`trust-web-core`'s `CorrelationIdFilter`).

For a call made with **no incoming request at all** - a scheduled batch, a
message-driven worker - there is normally nothing in MDC to propagate. This
starter generates an identifier in that case, sets it on the outgoing
call, and holds it in MDC **for the duration of that call only** (so it
appears in that call's own logs), then restores whatever was in MDC
before. It never overwrites an identifier already present: a batch run that
wants every call it makes to share one correlation identifier sets it
itself, once, at the start of the run - this starter then respects it for
every call, unchanged.

## Mutual TLS: presenting a client certificate

Some downstream services don't just check the bearer token in the request -
they also require the connection itself to be authenticated with a client
certificate (mutual TLS / mTLS), on top of anything relayed at the HTTP
layer. This is common at the edge of an organization rather than between
internal services: a payment network, a partner bank's API, a government
interconnection, or any B2B integration where the partner's security policy
mandates verifying *which system* is calling, independently of *which user*
is behind the call.

This is entirely native - Spring Boot's own
[`SslBundle`](https://docs.spring.io/spring-boot/reference/features/ssl.html)
abstraction, referenced by the transport property, no code in this starter
involved.

1. Declare the bundle - the keystore holding *this application's* client
   certificate and private key, and the truststore holding the certificate
   authority the *target* service's own certificate must chain up to - in
   the application's own configuration, exactly as you would for an
   embedded server's own TLS:

   ```yaml
   spring:
     ssl:
       bundle:
         jks:
           bank-mtls:
             key:
               alias: my-app
             keystore:
               location: file:/etc/trust/bank-mtls/keystore.p12
               password: ${BANK_MTLS_KEYSTORE_PASSWORD}
               type: PKCS12
             truststore:
               location: file:/etc/trust/bank-mtls/truststore.p12
               password: ${BANK_MTLS_TRUSTSTORE_PASSWORD}
               type: PKCS12
   ```

2. Reference that bundle by name from the group that needs it, under the
   native transport property:

   ```yaml
   spring:
     http:
       serviceclient:
         bank:                     # matches @ImportHttpServices(group = "bank")
           ssl:
             bundle: bank-mtls
   ```

Only the `bank` group's connections present this certificate; every other
group is unaffected. If the configured bundle name doesn't match any
declared `spring.ssl.bundle.*` bundle, the application fails to start with
a clear error rather than silently falling back to no client certificate -
native Spring Boot behavior, unchanged by this starter.

For a complete, runnable walkthrough - generating a real test certificate
pair and proving the handshake actually succeeds and actually fails when
expected - see [`MTLS-TESTING.md`](MTLS-TESTING.md).

## Prerequisites

- `spring-boot-starter-security-oauth2-client` on the classpath activates
  the native `OAuth2AuthorizedClientManager`-backed relay path (BFF mode,
  and any `@ClientRegistrationId`-annotated call).
- `spring-boot-starter-security-oauth2-resource-server` (optional at
  runtime) activates resource-server-mode token relay for unannotated
  calls made while the current authentication is a `JwtAuthenticationToken`
  (JWT) or a `BearerTokenAuthentication` (opaque token, RFC 7662
  introspection) - both relayed the same way, by the same interceptor.
  **A pure BFF application that never acts as a resource server can safely
  omit this dependency** - the relay interceptor for that mode is only
  added when the dependency is present, and nothing about it is required
  for `@ClientRegistrationId`-based relay to work.
- A `spring.security.oauth2.client.registration.<registration-id>` entry
  matching any `@ClientRegistrationId` used. For a `client_credentials`
  registration, that's the only prerequisite - this starter auto-configures
  a manager for it (see [Autonomous machine-to-machine calls](#autonomous-machine-to-machine-calls-client_credentials)).
  The same holds for a token-exchange registration (see
  [On behalf of the user](#on-behalf-of-the-user-token-exchange-rfc-8693)),
  which additionally needs the resource-server dependency, since the token
  it exchanges is the incoming one. Any other grant type still needs an application-supplied
  `OAuth2AuthorizedClientManager` bean able to authorize it.

## What this starter does not do (yet)

- **No bulkhead / concurrency limiting** - only retry and circuit breaking
  are implemented today.
- **No per-method timeout or circuit-breaker override** - both are
  per-group only; `@NoRetry` and `@NoTokenRelay` are the two override
  granularities finer than the group itself, and each applies to exactly
  one concern (retry, token relay respectively).
- **No generic relay for a request whose target isn't known at compile
  time** (a gateway, a proxy) - every capability here applies only to a
  group declared via `@ImportHttpServices`.

These are documented gaps, not silent ones - they reflect the starter's
current scope, not an oversight.
