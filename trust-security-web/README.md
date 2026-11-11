# trust-security-web

Servlet-side security pieces shared by the two Trust security starters,
so that a resource server and a BFF answer, log and propagate context the
same way. Applications do not declare it: both starters bring it and wire
every piece below.

## Where it sits

```text
trust-security-core  +  trust-web-core
          └──────┬─────────┘
       trust-security-web               ← this module
          ┌──────┴─────────┐
resource-server starter   oauth2-client starter
```

## What it provides

| Class | What it does |
|---|---|
| `AcrStepUpAccessDeniedHandler` | A refused `@RequiresAcr` becomes the RFC 9470 challenge: `401`, `WWW-Authenticate: Bearer error="insufficient_user_authentication", acr_values="strong"`, and a Problem Details body. Any other denial goes to the next handler. The ACR value is escaped as an RFC 9110 quoted-string, so it can never break the header. |
| `ProblemDetailsAccessDeniedHandler`, `ProblemDetailsAuthenticationEntryPoint` | Let Spring Security's own handler set the status and headers, then write an RFC 9457 body (`trust-web-core`'s `ProblemDetailsWriter`): `"Access is denied."` / `"Authentication is required to access this resource."` |
| `AuthenticatedSubjectMdcFilter` | Puts the caller's `sub` in the logging MDC under `subject` (JWT, OIDC session or opaque token), and restores the previous value when the request ends. |
| `SecurityContextTaskDecorator` | Carries the security context **and** the current request to `@Async` and executor tasks: without the request, a BFF could not find the session's token from another thread. The task gets its own copy of the context, and the executing thread's previous state is restored afterwards. |
| `NoForeignSecurityFilterChainCondition` | Lets each starter create its `SecurityFilterChain` unless the application declared its own - while tolerating the other Trust starter's chain when both run side by side. |
| `RequestPatterns` | The overlap check behind the starters' startup validations (two chains, or a tenant login path, competing for the same URLs). When in doubt it reports an overlap, so a conflict fails the startup instead of being silent. |

A log line then carries both the request and the caller:

```yaml
logging:
  pattern:
    console: "%d %-5level [correlationId=%X{correlationId}] [subject=%X{subject}] %logger - %msg%n"
```

```text
10:42:01.337 INFO [correlationId=4f6c…] [subject=47df2d67-…] c.e.DocumentController - document 12 updated
```

## Behaviors to know

- **Step-up is a `401`, not a `403`**: the caller is known but must
  authenticate more strongly. A BFF passes the challenge on to its page,
  which starts the step-up (`trust-security-oauth2-client-starter`'s
  `/oauth2/step-up`).
- **The async request context only lives as long as the request**: a task
  that outlives it (fire-and-forget) cannot rely on the session's token.
- **Every error body has the same shape** across Trust applications:
  `type`, `title`, `status`, `detail`, `instance`.

## Maven dependency

Only for a library built on it (applications get it through a starter):

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-security-web</artifactId>
</dependency>
```

No version: it comes from the `trust-dependencies` BOM (see the
[repository README](../README.md#use-it-in-an-application)).

Every package is `@NullMarked` (JSpecify) and checked by NullAway at build
time.
