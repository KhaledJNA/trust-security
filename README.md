# trust-security

[![build](https://github.com/KhaledJNA/trust-security/actions/workflows/build.yml/badge.svg)](https://github.com/KhaledJNA/trust-security/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Spring Boot starters and libraries that give an application its security
with a few properties: OAuth2 login for a BFF, JWT or opaque-token resource
servers, ACR step-up, claim → authority mapping, fine-grained authorization
delegated to a decision point (Keycloak Authorization Services provided),
and outgoing calls that carry the right token. Every module shares one
version.

To see them working together, with a local Keycloak and three sample
applications: [trust-getting-started](https://github.com/KhaledJNA/trust-getting-started).

## Modules

| Module | For | What it does |
|---|---|---|
| [`trust-security-oauth2-client-starter`](trust-security-oauth2-client-starter) | BFF | OIDC login, session, logout, ACR step-up (`/oauth2/step-up`), multi-tenant registrations |
| [`trust-security-resource-server-starter`](trust-security-resource-server-starter) | API | JWT (single or multi-issuer) or opaque tokens, audience check, `@RequiresAcr`, `@RequiresPermission` |
| [`trust-security-keycloak-authorization-starter`](trust-security-keycloak-authorization-starter) | API | `@RequiresPermission` decisions by Keycloak Authorization Services (UMA) |
| [`trust-rest-client-starter`](trust-rest-client-starter) | any | Outgoing HTTP clients: token relay, token exchange, `client_credentials`, retry, circuit breaker, mTLS |
| [`trust-security-test`](trust-security-test) | tests | `TestAuthorizationDecisionClient`: PERMIT/DENY from the test, no decision point |
| [`trust-resource-server-test`](trust-resource-server-test) | tests | `@WithTrustJwt`: a JWT claim set run through the application's real mapping |
| [`trust-oauth2-client-test`](trust-oauth2-client-test) | tests | `@WithTrustOidcUser`: the same for an OIDC login |
| [`trust-security-core`](trust-security-core) | (brought by the starters) | Annotations and provider-neutral rules |
| [`trust-security-web`](trust-security-web) | (brought by the starters) | Step-up challenge, Problem Details errors, MDC, async context |
| [`trust-web-core`](trust-web-core) | (brought by the starters) | Correlation id, RFC 9457 Problem Details |
| [`trust-dependencies`](trust-dependencies) | applications | The BOM: one version for every module above |
| [`trust-parent`](trust-parent) | these modules | Their build parent: Spring Boot version, NullAway, enforcer |
| [`trust-security-integration-tests`](trust-security-integration-tests) | this repository | Certification of the starters against a real Keycloak (Testcontainers) |

## Compatibility

| Trust | Java | Spring Boot | Spring Security |
|---|---|---|---|
| 0.0.1-SNAPSHOT | 21+ | 4.1.x (built and tested with 4.1.1) | 7.1.x |

## Use it in an application

Import the BOM once, then declare the modules you need without a version:

```xml
<dependencyManagement>
    <dependencies>
        <dependency>
            <groupId>com.trust</groupId>
            <artifactId>trust-dependencies</artifactId>
            <version>0.0.1-SNAPSHOT</version>
            <type>pom</type>
            <scope>import</scope>
        </dependency>
    </dependencies>
</dependencyManagement>

<dependencies>
    <dependency>
        <groupId>com.trust</groupId>
        <artifactId>trust-security-resource-server-starter</artifactId>
    </dependency>
    <dependency>
        <groupId>com.trust</groupId>
        <artifactId>trust-resource-server-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```

The application keeps its own `spring-boot-starter-parent` (or Spring Boot
BOM): `trust-dependencies` lists Trust modules only, so it never changes
the Spring versions an application chose. Pick a Spring Boot version from
the compatibility table.

The modules are not published to a Maven repository yet: install them
locally first (below).

## Build

Needs JDK 21+ (the Maven wrapper downloads Maven):

```bash
./mvnw install                          # every module, with its tests
./mvnw install -DskipTests              # faster
./mvnw install -Pintegration-tests      # plus the certification suite (needs Docker)
```

The build fails on a nullness error in a `@NullMarked` package (NullAway;
`-DskipNullAway` to skip), on a Trust dependency at another version than
the others, and on a JDK older than 21.

## Versioning

Every module has the same version, changed in one command:

```bash
./mvnw versions:set -DnewVersion=0.2.0 -DprocessAllModules -DgenerateBackupPoms=false
```

A module depends on the others without a version: `trust-parent` imports
`trust-dependencies`, so the build can only combine modules of the same
version.

## License

[Apache License 2.0](LICENSE).
