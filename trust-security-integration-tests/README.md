# trust-security-integration-tests

Provider certification bench for the Trust security platform: it proves that
Trust's provider-agnostic security building blocks (`trust-security-core`,
`trust-security-resource-server-starter`,
`trust-security-oauth2-client-starter`) genuinely work once wired to a real
Identity/Authorization Provider — today Keycloak, via its dedicated adapter
`trust-security-keycloak-authorization-starter`.

This module is an executable, self-contained test suite whose only purpose
is certification against a real provider. It is not a library: nothing
depends on it.

## Why this module exists

Trust ships three other libraries that let *applications* test their own
security **without** a real provider, **without** Docker, and **without** a
real network OAuth2/OIDC protocol exchange:

| Library | What it tests | What it deliberately does not test |
|---|---|---|
| `trust-security-test` | Application security wiring | Real Provider decisions (uses a fake PDP) |
| `trust-resource-server-test` | Trust's JWT claim → authority conversion | Real signature, JWKS, issuer, audience validation (uses a fixture JWT) |
| `trust-oauth2-client-test` | Trust's OIDC claim → authority/user mapping | The real OIDC network protocol (uses a fixture `OidcUser`) |

Those three are fast and deterministic by design — that is their value. But
none of them proves that Trust's contract with a *real* provider actually
holds. That is the gap `trust-security-integration-tests` fills:

```
Application-level tests (fast, no infrastructure)
  trust-security-test / trust-resource-server-test / trust-oauth2-client-test

Provider-level certification (this module)
  trust-security-integration-tests
  → real provider (Testcontainers), real protocols, real tokens, real adapters
```

This module does not depend on any of the three `trust-*-test`
libraries — the two levels are
complementary, not redundant: a scenario "already covered" at the
application level with a fake provider is not a substitute for proving the
same capability against a real one.

## Architecture

```
trust-security-integration-tests
├── contract/            Trust-facing scenarios — provider-agnostic
│   ├── resourceserver/   JWT and opaque-token modes
│   ├── authorization/    UMA, claim_token context
│   └── oauth2client/     BFF login, PKCE, step-up challenge, logout
│
├── provider/
│   └── keycloak/        Everything that starts, configures or talks to Keycloak
│
└── support/              Minimal Spring Boot harness applications wiring the real Trust starters
```

Rule (a convention kept in review, not checked by the build): code under
`contract/` describes an expected Trust behavior and never imports a Keycloak
class (`org.keycloak.*`, `dasniko.*`) directly — it only uses the public
facade of `provider.keycloak`: `KeycloakTestEnvironment` (container, realm
constants, real tokens, endpoints) and `KeycloakBrowserSimulator` (browser-like
login). Everything else in that package is package-private. This keeps every
scenario readable independently of which provider currently backs it.

**Keycloak is the only provider implemented today.** No `TrustProvider`
abstraction has been introduced: provider capabilities differ too much
(Keycloak: OIDC + JWT + a full PDP/UMA engine; a future Entra ID: OIDC + JWT
only; a future OPA: PDP only) for a shared contract to be meaningful yet
(YAGNI). Adding a provider later means adding a new `provider/<name>`
package next to `provider/keycloak`, with its own support classes — the
existing `contract/` scenarios stay unchanged for whatever that new provider
already covers.

## Test realm

Every scenario runs against a single Keycloak Testcontainer
(`quay.io/keycloak/keycloak:26.7.2`) importing a purpose-built, fully
artificial realm, `trust-integration` — independent of any business domain
or demo application:

| | |
|---|---|
| **Users** | `trust.user` (`TRUST_TEST_USER`, `TRUST_TEST_READER` on `trust-it-api`), `trust.admin` (`TRUST_TEST_ADMIN`), `trust.denied` (no role) |
| **Realm roles** | `TRUST_TEST_USER`, `TRUST_TEST_ADMIN` |
| **Client roles** | `TRUST_TEST_READER` (on `trust-it-api`) |
| **Clients** | `trust-it-bff` (confidential, Authorization Code + PKCE S256 required; password grant enabled only to issue tokens for the Resource Server/UMA scenarios), `trust-it-api` (resource server; its secret authenticates opaque-token introspection), `trust-it-api-downstream` (resource server, token-relay target), `trust-it-authorization` (Authorization Services enabled) |
| **Audience scopes** | optional client scopes `aud-trust-it-api`, `aud-trust-it-authorization`, `aud-trust-it-api-downstream` on `trust-it-bff`, so each scenario requests exactly the audience it needs |
| **Token lifespan** | Keycloak's default (5 min): long enough that no scenario can fail, or falsely pass a DENY, because a token expired mid-test |
| **Authorization resource** | `TestResource`, scopes `read` / `write` / `unassigned` |
| **Policies** | a Role Policy (`TRUST_TEST_USER`) and a real, deployed JavaScript Policy reading a `tenant` context claim |
| **Permissions** | `read` → Role Policy; `write` → the context-aware JavaScript Policy |

The realm, the deployed Script Policy provider, and every user/client/role
are provisioned automatically at container startup (realm import + Admin
Client) — nothing is created or configured by hand.

## What is currently certified against real Keycloak

| Capability | Real chain proven |
|---|---|
| JWT validation | Real container → real signed access token → real issuer/JWKS/signature check by Trust's `JwtDecoder` |
| Audience validation | A real token deliberately requested without the expected audience → Trust's audience validator rejects it |
| Realm role mapping | `realm_access.roles` → `ROLE_TRUST_TEST_USER` via Trust's authority converter |
| Client role mapping | `resource_access.trust-it-api.roles` → `ROLE_TRUST_TEST_READER` via the same converter |
| UMA authorization | `@RequiresPermission` → Trust's `KeycloakAuthorizationDecisionClient` → a real `uma-ticket` grant against real Keycloak Authorization Services |
| Role Policy PERMIT/DENY | A real decision changes with the caller's real role |
| Unknown resource / unknown scope / no matching permission | Real Keycloak denies each case for a structural reason, not a Trust-side shortcut |
| Context-driven (`claim_token`) authorization | `PermissionContextProvider` → real `claim_token` → a real, deployed JavaScript Policy reads the `tenant` attribute and PERMIT/DENY genuinely changes with its value |
| Untrusted issuer | A real, validly-signed token from another realm (other issuer, other keys) is rejected |
| Opaque-token mode (RFC 7662) | Real Keycloak introspection authenticated as `trust-it-api` → Trust's claim mapping on the introspection attributes → `@PreAuthorize`; inactive/foreign tokens rejected by the provider itself |
| Current user | Trust's `CurrentUserProvider` returns the real caller, in JWT and opaque mode alike |
| OAuth2 Client / BFF login | Real Authorization Code flow through Keycloak's real login form → real code exchange → HTTP session → mapped realm roles; wrong password leaves no session |
| PKCE | The real authorization request carries `code_challenge` with `S256` (and `state`, `nonce`); `trust-it-bff` requires PKCE on the Keycloak side, so every successful login also proves it |
| ACR step-up challenge | A session without the required ACR gets `401` + `WWW-Authenticate: ... insufficient_user_authentication, acr_values="strong"` on a `@RequiresAcr` endpoint |
| RP-initiated logout | CSRF-protected `POST /logout` ends the session and redirects to Keycloak's end-session endpoint with `id_token_hint`; without the CSRF token it is refused |

Every DENY scenario of the UMA suite re-uses the same token on a PERMIT path
afterwards: an expired or rejected token also ends in `403`, so the control
proves the DENY came from the policy decision itself.

See the test classes under `contract/` for the exact scenario-by-scenario
mapping; each carries its own Javadoc naming the real chain it exercises.

## Test inventory

| Test class | Harness / mode | Tests |
|---|---|---|
| `contract.resourceserver.ResourceServerJwtIntegrationTest` | `ResourceServerHarnessApplication`, JWT (`jwt.issuer-uri`), `client-id=trust-it-api` | 10 |
| `contract.resourceserver.ResourceServerOpaqueTokenIntegrationTest` | `ResourceServerHarnessApplication`, opaque token (`opaquetoken.introspection-uri`) | 6 |
| `contract.authorization.UmaAuthorizationIntegrationTest` | `ResourceServerHarnessApplication`, JWT, `client-id=trust-it-authorization` | 5 |
| `contract.authorization.UmaContextPolicyIntegrationTest` | same as above (shares its Spring context) | 2 |
| `contract.oauth2client.OAuth2ClientLoginIntegrationTest` | `OAuth2ClientHarnessApplication`, registration `keycloak` | 8 |
| **Total** | | **31** |

Configuration notes worth knowing before adding a scenario:

- **Harnesses.** `ResourceServerHarnessApplication` excludes the OAuth2 client
  auto-configuration and `OAuth2ClientHarnessApplication` excludes the
  resource-server and Keycloak-authorization ones, so each runs a single
  `SecurityFilterChain`. The resource-server endpoints read the caller through
  Trust's `CurrentUserProvider`, never a `Jwt` principal, so they serve the
  JWT and the opaque-token modes alike.
- **Opaque mode + UMA.** The Keycloak authorization adapter is on the harness
  classpath; without a `jwt.issuer-uri` to fall back on, it needs
  `trust.security.keycloak-authorization.issuer-uri` (set by the opaque test).
- **BFF redirect URI.** The BFF runs on a random port, so its redirect URI is
  registered on `trust-it-bff` through the Admin API once the application is
  up (`@BeforeEach`), never hard-coded.
- **Browser simulator.** `KeycloakBrowserSimulator` follows redirects across
  origins and keeps its own cookie jar (Keycloak's cookies are `Secure` even
  over plain `http://localhost`, which the JDK cookie handling refuses to
  replay). Use `getWithoutRedirect`/`postFormWithoutRedirect` to assert on a
  redirect itself.

## Not yet implemented

The following capabilities are part of this bench's target scope but do not
have a certifying scenario in this module yet — they are not silently
assumed to be covered elsewhere:

- Completing a real step-up (Keycloak ACR/LoA flow configured to issue a
  stronger `acr`), beyond the challenge itself
- Real refresh token flow
- Back-channel logout (`registerBffBackChannelLogoutUrl` is ready for it)
- Multi-issuer JWT mode
- Token relay (`trust-rest-client-starter`, service-to-service Bearer relay)

## Deliberately out of scope

Purely internal Trust behavior that a real provider cannot add proof value
to stays in its own module and is not duplicated here: MDC/correlation
propagation, `ProblemDetails` mapping, CSP/HSTS headers, CORS, async
`SecurityContext` propagation, `@ConditionalOnMissingBean` wiring, Spring
Boot auto-configuration metadata. The rule: this module covers only the
capabilities that genuinely need a real provider to be certified.

## Prerequisites

- Docker (any recent version, including 29+)
- JDK 21
- No local Keycloak install, no fixed port, no external secret

Testcontainers is the version Spring Boot manages (2.x, which supports
Docker 29+), and `testcontainers-keycloak` the release built against it:
keep the two in step when upgrading Spring Boot.

## Usage

From the root of this repository, which builds the libraries first:

```bash
./mvnw install -Pintegration-tests
```

The suite depends on the libraries exactly as an application would. Run
from the root, it uses the libraries of the same build; run from this
module, it uses the ones installed in `~/.m2`, so re-install a library
after changing it. From this module:

```bash
# Run the full suite
../mvnw clean verify

# Run a single scenario class
../mvnw test -Dtest=ResourceServerJwtIntegrationTest

# Run a single scenario
../mvnw test -Dtest=ResourceServerJwtIntegrationTest#givenRealValidToken_whenCallingRoleProtectedEndpoint_thenTheRealChainGrantsAccess

# Without network access (everything already in ~/.m2, Keycloak image already pulled)
../mvnw -o clean verify
```

The Keycloak container, realm import, and Authorization Services fixture are
started once per JVM (about 30 s) and torn down automatically by
Testcontainers - no manual setup or teardown step, and no fixed ordering
between test classes is required.
