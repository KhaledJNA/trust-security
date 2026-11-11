package com.trust.security.resourceserver.test;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Populates the {@code SecurityContext} for a test from a JWT <b>claim set</b>
 * loaded from a JSON file on the test classpath - not from a final,
 * already-decided set of authorities.
 * <p>
 * {@code @WithTrustJwt("user.json")} means: "here are the claims this user's
 * token carries." The application's real {@code Converter<Jwt, Collection<GrantedAuthority>>}
 * bean (e.g. {@code JwtClaimAuthoritiesConverter}, wired exactly as in
 * production by the resource server starter, or the application's own
 * override) is fetched from the test's Spring context and applied for real to
 * compute the resulting {@code GrantedAuthority} set and build a genuine
 * {@code JwtAuthenticationToken} - exactly what the real filter chain would
 * produce for a bearer token carrying these claims.
 * <p>
 * This is the key difference with a coarser {@code @WithRoleUser}-style
 * annotation that injects {@code ROLE_USER} directly: a claim mapping
 * misconfigured in the application (wrong path, wrong prefix) makes a test
 * using {@code @WithTrustJwt} fail exactly as it would in production, because
 * the real mapping logic runs.
 * <p>
 * What this deliberately does <b>not</b> exercise: RSA/JWKS signature
 * verification, the real issuer, {@code JwtDecoder}, or parsing of an actual
 * {@code Authorization: Bearer ...} header. Those belong to the resource
 * server starter's own internal tests - this module never contacts a network
 * or an identity provider.
 *
 * @see TrustTestJwts
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Documented
@WithSecurityContext(factory = WithTrustJwtSecurityContextFactory.class)
public @interface WithTrustJwt {

    /** Classpath location of the JSON claim set, e.g. {@code "user.json"} for {@code src/test/resources/user.json}. */
    String value();

    /** Overrides the {@code sub} claim found in the fixture, if any. Leave blank to use the fixture's own subject (or a neutral default if it has none). */
    String subject() default "";
}
