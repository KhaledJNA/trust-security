package com.trust.security.client.test;

import org.springframework.security.test.context.support.WithSecurityContext;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Populates the {@code SecurityContext} for a test from OIDC <b>claims</b>
 * loaded from a JSON file on the test classpath - not from a final,
 * already-decided set of authorities.
 * <p>
 * {@code @WithTrustOidcUser("user.json")} means: "here are the ID token
 * claims for this logged-in user." Exactly like the raw {@code OidcUserAuthority}
 * Spring itself builds during a real OIDC login, this raw authority is run
 * through the application's real {@code GrantedAuthoritiesMapper} bean (e.g.
 * {@code ClaimGrantedAuthoritiesMapper}) fetched from the test's Spring
 * context, so a misconfigured claim mapping makes a test fail exactly as it
 * would in production.
 * <p>
 * The resulting {@code Authentication} is a genuine {@code OAuth2AuthenticationToken}
 * wrapping a real {@code OidcUser} - the same types the application's code
 * actually sees at runtime - not a generic {@code UsernamePasswordAuthenticationToken}.
 * <p>
 * What this deliberately does <b>not</b> exercise: the authorization code
 * exchange, ID token signature verification, discovery, or any network call
 * to an identity provider. Those belong to the oauth2-client starter's own
 * internal tests - this module only represents the identity Spring Security
 * would have already established by the time application code runs.
 *
 * @see TrustTestOidcUsers
 */
@Retention(RetentionPolicy.RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Documented
@WithSecurityContext(factory = WithTrustOidcUserSecurityContextFactory.class)
public @interface WithTrustOidcUser {

    /** Classpath location of the JSON claim set, e.g. {@code "user.json"} for {@code src/test/resources/user.json}. */
    String value();

    /** Overrides the {@code sub} claim found in the fixture, if any. Leave blank to use the fixture's own subject (or a neutral default). */
    String subject() default "";

    /** Overrides the {@code acr} claim found in the fixture, if any - the main lever for step-up scenarios (e.g. {@code "strong"}). Leave blank to use the fixture's own value. */
    String acr() default "";

    /** The OAuth2 client registration id this authentication is attached to, as {@code OAuth2AuthenticationToken#getAuthorizedClientRegistrationId()} would return in production. */
    String registrationId() default "trust-test-provider";
}
