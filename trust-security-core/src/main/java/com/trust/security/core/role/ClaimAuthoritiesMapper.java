package com.trust.security.core.role;

import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * Turns arbitrary token claims into {@link GrantedAuthority} instances,
 * following a caller-supplied list of {@link AuthorityClaimMapping}.
 *
 * <p>This class knows nothing about any specific identity provider: it only
 * knows how to walk a path of nested {@code Map} keys and how to substitute
 * {@code {name}} placeholders using a variable map (e.g. the current OAuth2
 * client id) supplied by the caller. Which claims actually carry roles, and
 * under which name the current client id is exposed, is entirely a matter of
 * configuration.
 *
 * <p>A resolved claim value is turned into authorities according to its
 * shape: a {@code List} contributes one authority per element (unchanged
 * behavior); a single {@code String} contributes one authority for the whole
 * value, or one per token if the mapping declares a {@link AuthorityClaimMapping#separator()}
 * - never inferred from the value itself. Any other shape (e.g. a boolean or
 * a number) contributes nothing, the same as before, but is now logged at
 * {@code DEBUG} rather than left completely silent: converting such values
 * to a string was deliberately not chosen, since a boolean or numeric claim
 * is not an identity/role value and coercing it could produce a
 * meaningless authority (e.g. {@code "true"}) without the caller ever
 * intending it as one.
 */
public final class ClaimAuthoritiesMapper {

    private static final Logger log = LoggerFactory.getLogger(ClaimAuthoritiesMapper.class);

    private static final String PLACEHOLDER_FORMAT = "{%s}";
    private static final String PATH_SEPARATOR_REGEX = "\\.";

    private final List<AuthorityClaimMapping> mappings;

    public ClaimAuthoritiesMapper(@Nullable List<AuthorityClaimMapping> mappings) {
        this.mappings = mappings == null ? List.of() : List.copyOf(mappings);
    }

    /**
     * @param claims    token claims, whatever their origin; may be {@code null}
     * @param variables values substituted into {@code {name}} placeholders found
     *                  in a mapping's path (e.g. {@code Map.of("clientId", "my-app")});
     *                  may be {@code null} or omit a variable a path refers to, in
     *                  which case the placeholder simply never matches any claim.
     *                  A value may contain {@code "."} (e.g. a client id
     *                  {@code api.documents}): placeholders are substituted after
     *                  the path is split into segments
     * @return the matching authorities, empty if no mapping resolves to a value
     */
    public Collection<GrantedAuthority> map(
            @Nullable Map<String, ? extends @Nullable Object> claims,
            @Nullable Map<String, ? extends @Nullable String> variables) {

        if (claims == null || mappings.isEmpty()) {
            return List.of();
        }

        return mappings.stream()
                .flatMap(mapping -> valuesAt(
                                claims,
                                resolveSegments(mapping.path(), variables),
                                mapping.separator())
                        .stream()
                        .map(value -> mapping.prefix() + value))
                .distinct()
                .map(authority -> (GrantedAuthority) new SimpleGrantedAuthority(authority))
                .toList();
    }

    private static List<String> resolveSegments(
            String path, @Nullable Map<String, ? extends @Nullable String> variables) {

        return Arrays.stream(path.split(PATH_SEPARATOR_REGEX))
                .map(segment -> resolvePlaceholders(segment, variables))
                .toList();
    }

    private static String resolvePlaceholders(
            String segment, @Nullable Map<String, ? extends @Nullable String> variables) {

        if (variables == null || variables.isEmpty()) {
            return segment;
        }

        String resolved = segment;
        for (Map.Entry<String, ? extends @Nullable String> variable : variables.entrySet()) {
            String value = variable.getValue();
            if (value != null) {
                resolved = resolved.replace(PLACEHOLDER_FORMAT.formatted(variable.getKey()), value);
            }
        }
        return resolved;
    }

    private static List<String> valuesAt(
            Map<String, ? extends @Nullable Object> claims,
            List<String> segments,
            @Nullable String separator) {

        Object current = claims;

        for (String segment : segments) {
            if (!(current instanceof Map<?, ?> map)) {
                return List.of();
            }
            current = map.get(segment);
        }

        if (current instanceof Collection<?> values) {
            return stringElements(values, segments);
        }

        if (current instanceof String value) {
            return splitIfSeparatorConfigured(value, separator);
        }

        if (current != null) {
            log.debug("Claim at path '{}' has unsupported type {} for authority mapping "
                            + "(only List and String are supported); ignoring, no authority produced.",
                    String.join(".", segments), current.getClass().getName());
        }

        return List.of();
    }

    /**
     * Only non-blank strings become authorities: a {@code null}, blank or
     * non-string element (number, nested object) is skipped and logged, never
     * turned into e.g. {@code ROLE_null} - nor allowed to fail the whole mapping.
     */
    private static List<String> stringElements(Collection<?> values, List<String> segments) {
        List<String> strings = new ArrayList<>(values.size());
        for (Object element : values) {
            if (element instanceof String value && !value.isBlank()) {
                strings.add(value);
            } else {
                log.debug("Ignoring element {} of claim at path '{}': only non-blank strings are mapped "
                        + "to authorities.", element, String.join(".", segments));
            }
        }
        return strings;
    }

    private static List<String> splitIfSeparatorConfigured(String value, @Nullable String separator) {
        if (separator == null || separator.isEmpty()) {
            return value.isBlank() ? List.of() : List.of(value);
        }

        return Arrays.stream(value.split(Pattern.quote(separator)))
                .map(String::trim)
                .filter(token -> !token.isEmpty())
                .toList();
    }
}
