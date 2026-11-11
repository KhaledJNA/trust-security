package com.trust.security.client.tenant;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.Map;
import java.util.Optional;

/**
 * Resolves a {@code registrationId} from a path variable extracted with
 * Spring Security's own {@link PathPatternRequestMatcher} - the native
 * mechanism for URI-template variable extraction in this Spring Security
 * version; no custom path-parsing logic is written here.
 */
final class PathVariableTrustRegistrationIdResolver implements TrustRegistrationIdResolver {

    private final PathPatternRequestMatcher matcher;
    private final String variableName;
    private final Map<String, String> registrationIdsByVariable;

    PathVariableTrustRegistrationIdResolver(String requestPattern, String variableName, Map<String, String> mappings) {
        this.matcher = PathPatternRequestMatcher.pathPattern(requestPattern);
        this.variableName = variableName;
        this.registrationIdsByVariable = Map.copyOf(mappings);
    }

    @Override
    public Optional<String> resolve(HttpServletRequest request) {
        RequestMatcher.MatchResult result = matcher.matcher(request);
        if (!result.isMatch()) {
            return Optional.empty();
        }
        String value = result.getVariables().get(variableName);
        if (value == null) {
            return Optional.empty();
        }
        return Optional.ofNullable(registrationIdsByVariable.get(value));
    }
}
