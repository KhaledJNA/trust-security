# trust-resource-server-test

Test support for Trust platform Resource Servers.

## Purpose

`@WithTrustJwt("user.json")` does not mean "this user has `ROLE_USER`". It means "here are the claims of their JWT":

```
JSON claims (src/test/resources/user.json)
    ↓
test Jwt (technical, unsigned)
    ↓
the application's REAL Converter<Jwt, Collection<GrantedAuthority>>
    (JwtClaimAuthoritiesConverter, wired by ResourceServerAutoConfiguration
     - or the application's own override, if any)
    ↓
real JwtAuthenticationToken, carrying the authorities actually computed
    ↓
application code (endpoint protected by ROLE_USER, Jwt.getSubject(), business claim, ...)
```

This is the key difference from a coarser annotation such as `@WithRoleUser`, which would inject `ROLE_USER` directly: if the application's claim mapping is misconfigured (wrong path, wrong prefix), a test using `@WithTrustJwt` fails exactly as production would, because the real mapping runs - not a simulation.

## Maven dependency

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-resource-server-test</artifactId>
    <scope>test</scope>
</dependency>
```

No version: it comes from the `trust-dependencies` BOM (see the
[repository README](../README.md#use-it-in-an-application)).

## Fixture

```json
// src/test/resources/user.json
{
  "sub": "user-123",
  "preferred_username": "sample-user",
  "permissions": {
    "roles": ["USER"]
  }
}
```

## Minimal example

```java
@SpringBootTest
@AutoConfigureMockMvc
class DocumentsControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    @WithTrustJwt("user.json")
    void userCanReadDocuments() throws Exception {
        mockMvc.perform(get("/documents").with(testSecurityContext()))
                .andExpect(status().isOk());
    }
}
```

`.with(testSecurityContext())` (from `spring-security-test`) is required for the `SecurityContext` built by `@WithTrustJwt` to actually be applied to the `MockMvc` request - see the Javadoc of `WithSecurityContextTestExecutionListener`.

## Realistic example: a misconfiguration makes the test fail

```java
@Test
@WithTrustJwt("user.json")
void userCanReadDocuments() throws Exception {
    // If trust.security.authorities.mappings[0].path points to the wrong
    // claim path (e.g. "realm_access.roles" instead of "permissions.roles"
    // for this fixture), ROLE_USER is never produced and this test fails
    // with 403 - not because the test decides so, but because the
    // application's real mapping fails.
    mockMvc.perform(get("/documents").with(testSecurityContext()))
            .andExpect(status().isOk());
}
```

## Token dates

The test token is valid at test time: issued now, expiring in one hour. A
fixture can provide its own `iat`/`exp` (and `nbf`, and `auth_time` on the
OIDC side) as epoch seconds, as in a real decoded token, or as ISO-8601: they
are converted to `Instant` as the real decoder would, and take precedence
(useful for testing an expired token).

## What is actually tested

- Loading the JSON claims fixture.
- Building the `Jwt` (subject, nested claims).
- Calling the application's real `Converter<Jwt, Collection<GrantedAuthority>>`.
- The final authorities produced, carried by a real `JwtAuthenticationToken`.
- Application code reading `Jwt.getSubject()` or a business claim.

## What is deliberately bypassed

- RSA/JWKS signature verification.
- The real `issuer` and OIDC discovery.
- The `JwtDecoder` and parsing of a real `Authorization: Bearer ...` header.

These belong to the internal tests of `trust-security-resource-server-starter`.

## Note on `JwtAuthenticationConverter`

Spring Security's real `JwtAuthenticationConverter` automatically adds a `FACTOR_BEARER` authority (Spring Security 7 multi-factor support) on top of those produced by the claim mapping. This is framework behavior, not Trust's - don't be surprised to see it next to `ROLE_USER`.

## Relationship with the other two modules

- `trust-security-test` handles the `@RequiresPermission` decision (PERMIT/DENY) - not JWT identity.
- `trust-oauth2-client-test` handles OIDC identity on the BFF side - not the Resource Server.
- `trust-resource-server-test` is the only one of the three that builds a `Jwt` and calls a `JwtAuthenticationConverter`.
