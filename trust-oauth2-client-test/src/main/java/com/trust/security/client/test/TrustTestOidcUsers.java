package com.trust.security.client.test;

import org.jspecify.annotations.Nullable;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Builds test OIDC identities from claims, deliberately leaving everything a
 * real BFF login would validate untouched: no ID token signature, no
 * discovery document, no authorization code exchange, no network. See
 * {@link WithTrustOidcUser} for what this is meant to be used for.
 */
public final class TrustTestOidcUsers {

    private static final String TEST_ID_TOKEN_VALUE = "trust-test-id-token";
    private static final String NEUTRAL_SUBJECT = "test-subject";
    private static final Duration DEFAULT_LIFETIME = Duration.ofHours(1);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private TrustTestOidcUsers() {
    }

    /** Loads an OIDC claim set from a JSON file on the test classpath. */
    public static Map<String, Object> loadClaims(String classpathResource) {
        Objects.requireNonNull(classpathResource, "classpathResource must not be null");

        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = TrustTestOidcUsers.class.getClassLoader();
        }

        try (InputStream in = classLoader.getResourceAsStream(classpathResource)) {
            if (in == null) {
                throw new IllegalArgumentException(
                        "Trust OIDC claims fixture not found on the test classpath: '" + classpathResource
                                + "' (expected e.g. under src/test/resources/" + classpathResource + ")");
            }
            return OBJECT_MAPPER.readValue(in, new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException e) {
            throw new IllegalArgumentException(
                    "Failed to read Trust OIDC claims fixture: '" + classpathResource + "'", e);
        } catch (JacksonException e) {
            throw new IllegalArgumentException(
                    "Trust OIDC claims fixture is not valid JSON: '" + classpathResource + "'", e);
        }
    }

    /** Builds a technically-valid test ID token carrying exactly the given claims, with a neutral default subject if none is present. */
    public static OidcIdToken idToken(Map<String, Object> claims) {
        return idToken(claims, null, null);
    }

    /**
     * Same as {@link #idToken(Map)}, additionally overriding (or setting) the
     * {@code sub} and {@code acr} claims when non-null - the two most common
     * per-test variations (a different user, a different authentication
     * strength).
     * <p>
     * The token is valid now: issued now, expiring in one hour, unless the
     * claims carry their own {@code iat}/{@code exp} (epoch seconds or ISO-8601),
     * which then win.
     */
    public static OidcIdToken idToken(
            Map<String, Object> claims, @Nullable String subjectOverride, @Nullable String acrOverride) {
        Objects.requireNonNull(claims, "claims must not be null");

        Map<String, Object> effectiveClaims = new LinkedHashMap<>(claims);
        if (subjectOverride != null) {
            effectiveClaims.put(IdTokenClaimNames.SUB, subjectOverride);
        }
        effectiveClaims.putIfAbsent(IdTokenClaimNames.SUB, NEUTRAL_SUBJECT);
        convertTimestamps(effectiveClaims, IdTokenClaimNames.IAT, IdTokenClaimNames.EXP, IdTokenClaimNames.AUTH_TIME, "nbf");
        if (acrOverride != null) {
            effectiveClaims.put(IdTokenClaimNames.ACR, acrOverride);
        }

        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return OidcIdToken.withTokenValue(TEST_ID_TOKEN_VALUE)
                .issuedAt(now)
                .expiresAt(now.plus(DEFAULT_LIFETIME))
                .claims(c -> c.putAll(effectiveClaims))
                .build();
    }

    /**
     * Builds the {@link OAuth2AuthenticationToken} a real BFF login would
     * produce for a user carrying these claims: the raw {@link OidcUserAuthority}
     * Spring itself always creates for an OIDC login is run through the
     * application's real {@link GrantedAuthoritiesMapper} bean (e.g.
     * {@code ClaimGrantedAuthoritiesMapper}, wired exactly as in production),
     * exactly mirroring {@code OAuth2LoginAuthenticationProvider}'s own logic.
     *
     * @param authoritiesMapper the application's real mapper bean; may be
     *                          {@code null}, in which case only the raw
     *                          {@code OIDC_USER} authority is granted - useful
     *                          to prove a claim mapping is actually necessary
     */
    public static OAuth2AuthenticationToken authenticationToken(
            Map<String, Object> claims,
            @Nullable String subjectOverride,
            @Nullable String acrOverride,
            String registrationId,
            @Nullable GrantedAuthoritiesMapper authoritiesMapper) {

        Objects.requireNonNull(registrationId, "registrationId must not be null");

        OidcIdToken idToken = idToken(claims, subjectOverride, acrOverride);
        OidcUserAuthority rawAuthority = new OidcUserAuthority(idToken);
        Collection<GrantedAuthority> rawAuthorities = Set.of(rawAuthority);

        Collection<? extends GrantedAuthority> effectiveAuthorities = authoritiesMapper == null
                ? rawAuthorities
                : authoritiesMapper.mapAuthorities(rawAuthorities);

        DefaultOidcUser oidcUser = new DefaultOidcUser(effectiveAuthorities, idToken);

        return new OAuth2AuthenticationToken(oidcUser, effectiveAuthorities, registrationId);
    }

    /**
     * Turns numeric (epoch seconds, as in a decoded token copied into a
     * fixture) or ISO-8601 timestamps into {@link Instant}, as the real
     * decoder does - the builder rejects any other type.
     */
    private static void convertTimestamps(Map<String, Object> claims, String... names) {
        for (String name : names) {
            Object value = claims.get(name);
            if (value instanceof Number number) {
                claims.put(name, Instant.ofEpochSecond(number.longValue()));
            } else if (value instanceof String text) {
                claims.put(name, Instant.parse(text));
            }
        }
    }
}
