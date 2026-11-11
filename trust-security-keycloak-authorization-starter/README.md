# trust-security-keycloak-authorization-starter

Takes the decisions of `@RequiresPermission` with **Keycloak Authorization
Services** (UMA). Add the dependency to a resource server and every
permission check becomes a question to Keycloak's policies: no code, one
property.

It is the only Trust module that knows UMA. Everything else stays
provider-neutral: this starter is just an `AuthorizationDecisionClient`
(see `trust-security-core`).

## Where it sits

```text
@RequiresPermission(resource = "Document", scope = "write")
        │  trust-security-resource-server-starter (provider-neutral)
AuthorizationRequest(resource, action, context)
        │  this starter
POST {issuer}/protocol/openid-connect/token
     grant_type=urn:ietf:params:oauth:grant-type:uma-ticket
     audience=<client-id>   permission=Document#write   response_mode=decision
     claim_token=<context>  (Authorization: Bearer <caller's token>)
        │
Keycloak policies → {"result": true|false}
```

## Use it

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-security-keycloak-authorization-starter</artifactId>
</dependency>
```

No version: it comes from the `trust-dependencies` BOM (see the
[repository README](../README.md#use-it-in-an-application)).

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: https://keycloak.example/realms/my-realm   # also the realm asked for decisions
trust:
  security:
    resource-server:
      client-id: my-api        # audience check AND the UMA resource server (audience=)
    # keycloak-authorization:
    #   issuer-uri: ...        # only if the decision realm is not the JWT issuer
```

| Property | Required | Meaning |
|---|---|---|
| `trust.security.resource-server.client-id` | yes | The Keycloak client holding the resources, scopes and policies (sent as `audience`). |
| `trust.security.keycloak-authorization.issuer-uri` | no | Realm to ask; defaults to `spring.security.oauth2.resourceserver.jwt.issuer-uri`. |

The application fails to start, naming the property, if either value is
missing. Declaring your own `AuthorizationDecisionClient` bean replaces
this one.

## Keycloak side

On the client named by `client-id`:

1. **Authorization** enabled (Client → Settings → Authorization);
2. a **resource** per `@RequiresPermission(resource = ...)`, with a
   **scope** per `scope = ...` (`Document` with `read`, `write`);
3. **policies** (role, user, group, regex, time, JavaScript…);
4. **permissions** linking a resource's scope to policies.

The names must match the annotations exactly: an unknown resource or scope
is answered `400` by Keycloak, refused here and logged at `WARN`.

### Context-driven decisions

The map returned by the method's `PermissionContextProvider` is sent as
`claim_token` (each value as a one-element list). Keycloak exposes it to
policies as context attributes: a **regex policy** with *Apply policy to
context attributes* on, or a JavaScript policy reading
`$evaluation.getContext().getAttributes().getValue("tenant").asString(0)`
(deployed as a script provider: Keycloak refuses inline JavaScript
policies by default).
[`trust-sample-api`](https://github.com/KhaledJNA/trust-getting-started/tree/main/trust-sample-api)
(in `trust-getting-started`) has a complete example: write allowed only for a
manager **and** a document of `tenant-a`.

## Behavior

| Keycloak answers | Result |
|---|---|
| `200 {"result": true}` | granted |
| `403` `not_authorized` (a policy said no) | denied, logged at `DEBUG` |
| `403` with another body (configuration problem) | denied, logged at `WARN` |
| `400` (unknown resource or scope) | denied, logged at `WARN` |

Logs never contain the access token or the `claim_token`.

## Known limitations

- **JWT callers only.** The caller's token is forwarded to Keycloak, and
  only a `JwtAuthenticationToken` is used: in an **opaque-token**
  resource server (RFC 7662 introspection) every `@RequiresPermission`
  check is **denied**. Supply your own `AuthorizationDecisionClient` for
  that mode.
- **One HTTP call per check**, without caching.
- **No timeout** is set on the HTTP client: a slow Keycloak holds the
  request thread.
- Any other failure (Keycloak down, `5xx`, `401` for an expired token)
  propagates as an exception: the request fails (fail closed), but with a
  `500`, not a `403`.

## Proven against a real Keycloak

`trust-security-integration-tests` runs these decisions against a real
Keycloak container: role policy PERMIT/DENY, unknown resource or scope, no
matching permission, and context-driven decisions through a deployed
JavaScript policy.
