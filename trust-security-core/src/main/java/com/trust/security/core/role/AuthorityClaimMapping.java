package com.trust.security.core.role;

import java.util.Objects;

import org.jspecify.annotations.Nullable;

/**
 * Declares where to find authority values inside a claim set, and which
 * prefix to apply once found.
 *
 * <p>{@code path} addresses a value nested inside {@code Map}s, using
 * {@code "."} as a separator (e.g. {@code "permissions.roles"}). A path
 * segment may contain a {@code "{name}"} placeholder, resolved against a
 * caller-supplied variable map at mapping time (e.g.
 * {@code "application.{clientId}.roles"}).
 *
 * <p>{@code separator} is optional (pass {@code null}, or omit it from
 * configuration) and only affects a resolved value that is a single
 * {@link String}: absent, that whole string becomes one authority value; a
 * splitting behavior is never inferred from the value's content (e.g. the
 * presence of a space) - it must be declared explicitly here, since a claim
 * such as a person's full name would otherwise be split into meaningless
 * authorities. A resolved value that is already a {@code List} is never
 * affected by {@code separator}: each element is used as-is.
 *
 * <p>This type carries no Spring Boot annotation on purpose: it is meant to
 * be reused as a {@code @ConfigurationProperties} binding target by
 * different starters, without making trust-security-core depend on
 * Spring Boot's configuration-properties machinery. It deliberately has a
 * single constructor (the canonical one): Spring Boot's constructor binding
 * for records requires exactly one to reliably bind {@code path}/{@code prefix}/
 * {@code separator} from {@code @ConfigurationProperties} - an additional
 * overload, even a source-compatible convenience one, makes the binder fall
 * back to bean-style binding, which records don't support (no setters),
 * and every property is silently left unbound (verified: this exact
 * regression was caught by {@code AuthoritiesMappingPropertiesTest} when a
 * two-argument convenience constructor was tried during development).
 */
public record AuthorityClaimMapping(String path, String prefix, @Nullable String separator) {

    public AuthorityClaimMapping {
        Objects.requireNonNull(path, "path must not be null");
        Objects.requireNonNull(prefix, "prefix must not be null");
    }
}
