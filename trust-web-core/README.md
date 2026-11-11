# trust-web-core

Servlet building blocks shared by every Trust web starter, with no security
in them: a **correlation id** for each request, and the **RFC 9457 Problem
Details** format used for every error response.

## Where it sits

```text
trust-web-core                         ← this module (no Spring Security)
   ↑
trust-security-web ─┬─ trust-security-resource-server-starter
                    └─ trust-security-oauth2-client-starter
trust-rest-client-starter              (reads the correlation id, parses Problem Details)
```

Applications never declare it: every starter above brings it.

## Correlation id

`CorrelationIdFilter` gives every request an identifier that follows it
through the logs and into outgoing calls:

- the incoming `X-Correlation-ID` header is reused when it is safe: 1 to
  128 characters among `A-Z a-z 0-9 . _ : -`; anything else (absent, too
  long, a log-injection attempt) is replaced by a random UUID;
- the value is echoed in the response's `X-Correlation-ID` header;
- it is in the logging MDC under `correlationId` for the whole request;
- `trust-rest-client-starter` forwards it on every outgoing call.

```yaml
logging:
  pattern:
    console: "%d %-5level [correlationId=%X{correlationId}] %logger - %msg%n"
```

`CorrelationIdFilterAutoConfiguration` registers the filter first in the
servlet chain (`Ordered.HIGHEST_PRECEDENCE`). This module does not activate
it on its own (it has no `AutoConfiguration.imports`): each starter that
needs it lists it, and Spring Boot keeps a single registration when several
starters are present. To replace it, declare a bean named
`correlationIdFilterRegistration`.

| Constant | Value |
|---|---|
| `CorrelationId.HEADER_NAME` | `X-Correlation-ID` |
| `CorrelationId.MDC_KEY` | `correlationId` |

## Problem Details

| Class | Side | Does |
|---|---|---|
| `ProblemDetailsWriter` | server | Writes an `application/problem+json` body for the status already set on the response: `title` = the status reason phrase, `detail` = the given message, `instance` = the request path. Does nothing if the response is already committed. |
| `ProblemDetailsReader` | client | Reads a response body back into a `ProblemDetail` when its content type is `application/problem+json`; returns empty for any other content type, an empty body or invalid JSON (a proxy's HTML error page is an absence of details, not a failure). |

Both take the application's `ObjectMapper`. The reader relies on the
`ProblemDetailJacksonMixin` that Spring Boot registers on it, so that RFC
9457 extension members are kept.

## Maven dependency

Only for a library that builds on it (applications get it through a
starter):

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-web-core</artifactId>
</dependency>
```

No version: it comes from the `trust-dependencies` BOM (see the
[repository README](../README.md#use-it-in-an-application)).

## Known limitation

`ProblemDetailsWriter` builds `instance` with `URI.create(requestURI)`: a
request path the servlet container accepts but that is not a valid URI
(possible when the container is configured with relaxed path characters)
makes the error response itself fail with a 500.
