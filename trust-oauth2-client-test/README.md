# trust-oauth2-client-test

Test support for Trust platform BFFs (`trust-security-oauth2-client-starter`).

## Purpose

`@WithTrustOidcUser("user.json")` represents the OIDC identity as Spring Security has already established it by the time application code runs - not an already-decided final result:

```
OIDC claims (src/test/resources/user.json)
    ↓
test OidcIdToken (technical, unsigned)
    ↓
raw OidcUserAuthority (as in a real OIDC login)
    ↓
the application's REAL GrantedAuthoritiesMapper
    (ClaimGrantedAuthoritiesMapper, wired by OAuth2ClientAutoConfiguration)
    ↓
real OAuth2AuthenticationToken, carrying a real OidcUser
    ↓
application code (@PreAuthorize("hasRole('USER')"), @RequiresAcr, /api/me, ...)
```

Exactly as for the Resource Server, a misconfigured claim mapping makes the test fail - not a simulation that ignores it.

## Maven dependency

```xml
<dependency>
    <groupId>com.trust</groupId>
    <artifactId>trust-oauth2-client-test</artifactId>
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
class ProfileControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    @WithTrustOidcUser("user.json")
    void meReturnsTheAuthenticatedUser() throws Exception {
        mockMvc.perform(get("/api/me").with(testSecurityContext()))
                .andExpect(status().isOk());
    }
}
```

## ACR / step-up scenario

```java
@Test
@WithTrustOidcUser("user.json")  // no strong acr in the fixture
void insufficientAcr_triggersStepUp() {
    // call a @RequiresAcr("strong") endpoint/service
    // -> AuthorizationDeniedException / the application's step-up response
}

@Test
@WithTrustOidcUser(value = "user.json", acr = "strong")
void strongAcr_grantsAccess() {
    // same call -> access granted
}
```

This exercises the real `AcrAuthorization`/`@RequiresAcr` from `trust-security-core`. This module does **not** simulate the Authorization Code protocol or the `/oauth2/step-up` redirect: it represents the identity once established, as intended.

## Token dates

The test token is valid at test time: issued now, expiring in one hour. A
fixture can provide its own `iat`/`exp` (and `nbf`, and `auth_time` on the
OIDC side) as epoch seconds, as in a real decoded token, or as ISO-8601: they
are converted to `Instant` as the real decoder would, and take precedence
(useful for testing an expired token).

## What is actually tested

- Loading the OIDC claims JSON fixture.
- Building the `OidcIdToken` and the raw `OidcUserAuthority`.
- Calling the application's real `GrantedAuthoritiesMapper` (if there is one in the test context - otherwise only the raw `OIDC_USER` authority is granted, which is a valid scenario, not an error).
- The real `@RequiresAcr` / `AcrAuthorization` with the `acr` value from the fixture or the annotation.
- The `OAuth2AuthenticationToken`/`OidcUser` type actually seen by application code.

## What is deliberately bypassed

- The authorization code exchange (`authorization_code` grant).
- ID Token signature verification, OIDC discovery, any network call to the IdP.
- The real HTTP step-up redirect (`/oauth2/step-up`): only the BFF's behavior once the identity is represented is tested.

## Relationship with the other two modules

- `trust-security-test` handles the `@RequiresPermission` decision (PERMIT/DENY).
- `trust-resource-server-test` handles JWT identity on the Resource Server side.
- `trust-oauth2-client-test` is the only one of the three that builds an `OidcUser`/`OAuth2AuthenticationToken` and carries the ACR.
