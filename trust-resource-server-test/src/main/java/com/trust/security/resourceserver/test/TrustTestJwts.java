package com.trust.security.resourceserver.test;

import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import tools.jackson.core.JacksonException;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Builds test {@link Jwt} instances from claims, deliberately leaving
 * everything a real resource server would validate untouched: no signature,
 * no {@code JwtDecoder}, no issuer, no JWKS, no network. See {@link WithTrustJwt}
 * for what this is meant to be used for and what it is not.
 */
public final class TrustTestJwts {

    private static final String TEST_TOKEN_VALUE = "trust-test-jwt";
    private static final String NEUTRAL_SUBJECT = "test-subject";
    private static final Duration DEFAULT_LIFETIME = Duration.ofHours(1);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private TrustTestJwts() {
    }

    /**
     * Loads a claim set from a JSON file found on the test classpath (e.g.
     * {@code src/test/resources/user.json} referenced as {@code "user.json"}).
     */
    public static Map<String, Object> loadClaims(String classpathResource) {
        Objects.requireNonNull(classpathResource, "classpathResource must not be null");

        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
        if (classLoader == null) {
            classLoader = TrustTestJwts.class.getClassLoader();
        }

        try (InputStream in = classLoader.getResourceAsStream(classpathResource)) {
            if (in == null) {
                throw new IllegalArgumentException(
                        "Trust JWT claims fixture not found on the test classpath: '" + classpathResource
                                + "' (expected e.g. under src/test/resources/" + classpathResource + ")");
            }
            return OBJECT_MAPPER.readValue(in, new TypeReference<Map<String, Object>>() {
            });
        } catch (IOException e) {
            throw new IllegalArgumentException(
                    "Failed to read Trust JWT claims fixture: '" + classpathResource + "'", e);
        } catch (JacksonException e) {
            throw new IllegalArgumentException(
                    "Trust JWT claims fixture is not valid JSON: '" + classpathResource + "'", e);
        }
    }

    /** Builds a technically-valid test {@link Jwt} carrying exactly the given claims, with a neutral default subject if none is present. */
    public static Jwt jwt(Map<String, Object> claims) {
        return jwt(claims, null);
    }

    /**
     * Same as {@link #jwt(Map)}, but overrides (or sets) the {@code sub} claim
     * with {@code subjectOverride} when non-null.
     * <p>
     * The token is valid now: issued now, expiring in one hour, unless the
     * claims carry their own {@code iat}/{@code exp} (epoch seconds or ISO-8601),
     * which then win - e.g. to test how application code handles an expired token.
     */
    public static Jwt jwt(Map<String, Object> claims, @Nullable String subjectOverride) {
        Objects.requireNonNull(claims, "claims must not be null");

        Map<String, Object> effectiveClaims = new LinkedHashMap<>(claims);
        if (subjectOverride != null) {
            effectiveClaims.put(JwtClaimNames.SUB, subjectOverride);
        }
        effectiveClaims.putIfAbsent(JwtClaimNames.SUB, NEUTRAL_SUBJECT);
        convertTimestamps(effectiveClaims, JwtClaimNames.IAT, JwtClaimNames.EXP, JwtClaimNames.NBF);

        Instant now = Instant.now().truncatedTo(ChronoUnit.SECONDS);
        return Jwt.withTokenValue(TEST_TOKEN_VALUE)
                .header("alg", "none")
                .issuedAt(now)
                .expiresAt(now.plus(DEFAULT_LIFETIME))
                .claims(c -> c.putAll(effectiveClaims))
                .build();
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
