package com.trust.keycloak.authorization;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import com.trust.security.core.authorization.AuthorizationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.ObjectMapper;

import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

/**
 * Translates the generic {@link AuthorizationRequest} into a Keycloak
 * Authorization Services / UMA ticket request. This is the only place in
 * the Trust security libraries allowed to know about UMA vocabulary
 * (access token, audience, {@code resource#scope} permission string,
 * {@code claim_token}).
 * <p>
 * {@link AuthorizationRequest#authentication()} must be a
 * {@link JwtAuthenticationToken} for a decision to be possible at all
 * (a bearer token has to be forwarded to Keycloak's token endpoint) - any
 * other type, including {@code null}, is denied rather than raising an
 * exception.
 */
public final class KeycloakAuthorizationDecisionClient
        implements AuthorizationDecisionClient {

    private static final Logger log =
            LoggerFactory.getLogger(KeycloakAuthorizationDecisionClient.class);

    private static final String UMA_GRANT_TYPE =
            "urn:ietf:params:oauth:grant-type:uma-ticket";

    private static final String CLAIM_TOKEN_FORMAT =
            "urn:ietf:params:oauth:token-type:jwt";

    /**
     * Keycloak's own error classification for a 403 issued because a policy
     * genuinely denied the requested permission (as opposed to a malformed
     * request or a misconfigured resource/scope/policy, which Keycloak also
     * reports through other error descriptions on the same 403 status).
     */
    private static final String EXPECTED_DENIAL_ERROR_DESCRIPTION = "not_authorized";

    private final RestClient restClient;
    private final String tokenUri;
    private final String resourceServer;
    private final ObjectMapper objectMapper;

    public KeycloakAuthorizationDecisionClient(
            RestClient restClient,
            String tokenUri,
            String resourceServer,
            ObjectMapper objectMapper) {

        this.restClient = Objects.requireNonNull(
                restClient,
                "restClient must not be null"
        );

        this.tokenUri = Objects.requireNonNull(
                tokenUri,
                "tokenUri must not be null"
        );

        this.resourceServer = Objects.requireNonNull(
                resourceServer,
                "resourceServer must not be null"
        );

        this.objectMapper = Objects.requireNonNull(
                objectMapper,
                "objectMapper must not be null"
        );
    }

    @Override
    public boolean isAllowed(AuthorizationRequest request) {

        if (!(request.authentication() instanceof JwtAuthenticationToken jwtAuthentication)) {
            return false;
        }

        String accessToken = jwtAuthentication.getToken().getTokenValue();

        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();

        form.add("grant_type", UMA_GRANT_TYPE);
        form.add("audience", resourceServer);
        form.add("permission", request.resource() + "#" + request.action());
        form.add("response_mode", "decision");

        Map<String, String> context = request.context();
        if (context != null && !context.isEmpty()) {
            form.add("claim_token", encodeContext(context));
            form.add("claim_token_format", CLAIM_TOKEN_FORMAT);
        }

        try {
            DecisionResponse response = restClient.post()
                    .uri(tokenUri)
                    .headers(headers -> headers.setBearerAuth(accessToken))
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(DecisionResponse.class);

            return response != null && response.result();

        } catch (HttpClientErrorException.Forbidden exception) {
            logForbidden(exception, request);
            return false;
        } catch (HttpClientErrorException.BadRequest exception) {
            logBadRequest(exception, request);
            return false;
        }
    }

    /**
     * Keycloak answers 400 ({@code invalid_resource}, {@code invalid_scope})
     * when the permission names a resource or scope it does not know: a
     * configuration mismatch between {@code @RequiresPermission} and Keycloak
     * Authorization Services. Denied (fail closed) instead of surfacing as a
     * 500, and logged at WARN so the mismatch is visible.
     */
    private void logBadRequest(HttpClientErrorException.BadRequest exception, AuthorizationRequest request) {
        log.warn("Keycloak rejected permission '{}#{}' on resource server '{}' as invalid - check that this "
                        + "resource and scope exist in Keycloak Authorization Services: {}",
                request.resource(), request.action(), resourceServer, exception.getResponseBodyAsString());
    }

    /**
     * Logs a Keycloak 403 without ever including the access token, the
     * claim_token, or any other request credential - only the business
     * resource/action being checked and Keycloak's own error body, which
     * contains just an {@code error}/{@code error_description} pair.
     * <p>
     * The HTTP outcome is unaffected either way: this is purely about
     * distinguishing, in the logs, an expected policy denial (DEBUG) from a
     * response shape that suggests a configuration problem (WARN) - fail
     * closed either way.
     */
    private void logForbidden(HttpClientErrorException.Forbidden exception, AuthorizationRequest request) {
        String responseBody = exception.getResponseBodyAsString();

        if (responseBody != null && responseBody.contains(EXPECTED_DENIAL_ERROR_DESCRIPTION)) {
            log.debug("Keycloak denied permission '{}#{}' for resource server '{}': {}",
                    request.resource(), request.action(), resourceServer, responseBody);
        } else {
            log.warn("Keycloak returned 403 for permission '{}#{}' on resource server '{}' with an "
                    + "unexpected response body - check the resource/scope/policy configuration in "
                    + "Keycloak Authorization Services: {}",
                    request.resource(), request.action(), resourceServer, responseBody);
        }
    }

    private String encodeContext(Map<String, String> context) {

        try {
            Map<String, List<String>> claims = context.entrySet()
                    .stream()
                    .collect(Collectors.toMap(
                            Map.Entry::getKey,
                            entry -> List.of(entry.getValue())
                    ));

            byte[] json = objectMapper.writeValueAsBytes(claims);

            return Base64.getEncoder().encodeToString(json);

        } catch (JacksonException exception) {
            throw new IllegalStateException(
                    "Unable to encode authorization context",
                    exception
            );
        }
    }

    private record DecisionResponse(boolean result) {
    }
}
