package com.trust.keycloak.authorization;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.trust.security.core.authorization.AuthorizationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import tools.jackson.core.exc.JacksonIOException;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withBadRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withForbiddenRequest;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Behavioral tests for {@link KeycloakAuthorizationDecisionClient}, the only
 * place in the Trust security libraries allowed to know about Keycloak's UMA
 * grant flow. Verifies the exact wire contract against Keycloak's token
 * endpoint using {@link MockRestServiceServer}, without any real network call.
 */
class KeycloakAuthorizationDecisionClientTest {

    private static final String TOKEN_URI = "https://idp.example.com/realms/lab/protocol/openid-connect/token";
    private static final String RESOURCE_SERVER = "sample-api";

    private RestClient.Builder restClientBuilder;
    private MockRestServiceServer server;
    private ObjectMapper objectMapper;
    private KeycloakAuthorizationDecisionClient client;

    private ListAppender<ILoggingEvent> logAppender;
    private Logger clientLogger;

    @BeforeEach
    void setUp() {
        restClientBuilder = RestClient.builder();
        server = MockRestServiceServer.bindTo(restClientBuilder).build();
        objectMapper = new ObjectMapper();
        client = new KeycloakAuthorizationDecisionClient(
                restClientBuilder.build(), TOKEN_URI, RESOURCE_SERVER, objectMapper);

        clientLogger = (Logger) org.slf4j.LoggerFactory.getLogger(KeycloakAuthorizationDecisionClient.class);
        clientLogger.setLevel(Level.DEBUG);
        logAppender = new ListAppender<>();
        logAppender.start();
        clientLogger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        clientLogger.detachAppender(logAppender);
    }

    private static JwtAuthenticationToken jwtAuthentication(String tokenValue) {
        Jwt jwt = Jwt.withTokenValue(tokenValue)
                .header("alg", "none")
                .claim("sub", "user-1")
                .issuedAt(Instant.EPOCH)
                .expiresAt(Instant.EPOCH.plusSeconds(3600))
                .build();
        return new JwtAuthenticationToken(jwt);
    }

    private static AuthorizationRequest request(Authentication authentication, Map<String, String> context) {
        return new AuthorizationRequest(authentication, "document", "modify", context);
    }

    @Test
    void givenNullRestClient_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() ->
                new KeycloakAuthorizationDecisionClient(null, TOKEN_URI, RESOURCE_SERVER, objectMapper));
    }

    @Test
    void givenNullTokenUri_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() ->
                new KeycloakAuthorizationDecisionClient(restClientBuilder.build(), null, RESOURCE_SERVER, objectMapper));
    }

    @Test
    void givenNullResourceServer_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() ->
                new KeycloakAuthorizationDecisionClient(restClientBuilder.build(), TOKEN_URI, null, objectMapper));
    }

    @Test
    void givenNullObjectMapper_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() ->
                new KeycloakAuthorizationDecisionClient(restClientBuilder.build(), TOKEN_URI, RESOURCE_SERVER, null));
    }

    @Test
    void givenNonJwtAuthentication_whenCheckingPermission_thenAccessIsDeniedWithoutAnyHttpCall() {
        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of());

        boolean allowed = client.isAllowed(request(authentication, Map.of()));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenNullAuthentication_whenCheckingPermission_thenAccessIsDeniedWithoutAnyHttpCall() {
        boolean allowed = client.isAllowed(request(null, Map.of()));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenEmptyContext_whenCheckingPermission_thenUmaTicketFormIsPostedWithoutClaimToken() {
        MultiValueMap<String, String> expectedForm = new LinkedMultiValueMap<>();
        expectedForm.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        expectedForm.add("audience", RESOURCE_SERVER);
        expectedForm.add("permission", "document#modify");
        expectedForm.add("response_mode", "decision");

        server.expect(requestTo(TOKEN_URI))
                .andExpect(method(HttpMethod.POST))
                .andExpect(header(HttpHeaders.AUTHORIZATION, "Bearer the-access-token"))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andExpect(content().formData(expectedForm))
                .andRespond(withSuccess("{\"result\":true}", MediaType.APPLICATION_JSON));

        boolean allowed = client.isAllowed(
                request(jwtAuthentication("the-access-token"), Map.of()));

        assertThat(allowed).isTrue();
        server.verify();
    }

    @Test
    void givenNonEmptyContext_whenCheckingPermission_thenClaimTokenIsBase64EncodedJsonWithCorrectFormat() throws Exception {
        String expectedClaimToken = java.util.Base64.getEncoder().encodeToString(
                objectMapper.writeValueAsBytes(Map.of("tenant", List.of("tenant-a"))));

        MultiValueMap<String, String> expectedForm = new LinkedMultiValueMap<>();
        expectedForm.add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket");
        expectedForm.add("audience", RESOURCE_SERVER);
        expectedForm.add("permission", "document#modify");
        expectedForm.add("response_mode", "decision");
        expectedForm.add("claim_token", expectedClaimToken);
        expectedForm.add("claim_token_format", "urn:ietf:params:oauth:token-type:jwt");

        server.expect(requestTo(TOKEN_URI))
                .andExpect(method(HttpMethod.POST))
                .andExpect(content().formData(expectedForm))
                .andRespond(withSuccess("{\"result\":true}", MediaType.APPLICATION_JSON));

        boolean allowed = client.isAllowed(
                request(jwtAuthentication("the-access-token"), Map.of("tenant", "tenant-a")));

        assertThat(allowed).isTrue();
        server.verify();
    }

    @Test
    void givenDecisionResponseResultTrue_whenCheckingPermission_thenTrueIsReturned() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withSuccess("{\"result\":true}", MediaType.APPLICATION_JSON));

        boolean allowed = client.isAllowed(request(jwtAuthentication("token"), Map.of()));

        assertThat(allowed).isTrue();
    }

    @Test
    void givenDecisionResponseResultFalse_whenCheckingPermission_thenFalseIsReturned() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withSuccess("{\"result\":false}", MediaType.APPLICATION_JSON));

        boolean allowed = client.isAllowed(request(jwtAuthentication("token"), Map.of()));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenExpectedPolicyDenial403_whenCheckingPermission_thenFalseIsReturnedAndExceptionIsNotPropagated() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withForbiddenRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"access_denied\",\"error_description\":\"not_authorized\"}"));

        boolean allowed = client.isAllowed(request(jwtAuthentication("token"), Map.of()));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenUnexpected403ResponseBody_whenCheckingPermission_thenStillFalseAndExceptionIsNotPropagated() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withForbiddenRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"invalid_scope\",\"error_description\":\"unknown scope\"}"));

        boolean allowed = client.isAllowed(request(jwtAuthentication("token"), Map.of()));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenKeycloak400ForUnknownResource_whenCheckingPermission_thenFalseIsReturnedInsteadOfAnError() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withBadRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"invalid_resource\",\"error_description\":\"Resource with id [Unknown] does not exist.\"}"));

        boolean allowed = client.isAllowed(request(jwtAuthentication("token"), Map.of()));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenPlain403WithNoBody_whenCheckingPermission_thenFalseIsReturned() {
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withForbiddenRequest());

        boolean allowed = client.isAllowed(request(jwtAuthentication("token"), Map.of()));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenContextEncodingFails_whenCheckingPermissionWithContext_thenIllegalStateExceptionIsThrown() {
        ObjectMapper failingMapper = mock(ObjectMapper.class);
        JacksonIOException encodingFailure = JacksonIOException.construct(new IOException("boom"));
        given(failingMapper.writeValueAsBytes(any())).willThrow(encodingFailure);

        KeycloakAuthorizationDecisionClient failingClient = new KeycloakAuthorizationDecisionClient(
                restClientBuilder.build(), TOKEN_URI, RESOURCE_SERVER, failingMapper);

        assertThatIllegalStateException()
                .isThrownBy(() -> failingClient.isAllowed(
                        request(jwtAuthentication("token"), Map.of("tenant", "tenant-a"))))
                .withMessage("Unable to encode authorization context")
                .withCause(encodingFailure);
    }

    @Test
    void givenExpectedPolicyDenial403_whenCheckingPermission_thenTheAccessTokenIsNeverLogged() {
        String secretToken = "super-secret-access-token-value";
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withForbiddenRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"access_denied\",\"error_description\":\"not_authorized\"}"));

        client.isAllowed(request(jwtAuthentication(secretToken), Map.of()));

        assertThat(logAppender.list)
                .extracting(ILoggingEvent::getFormattedMessage)
                .noneMatch(message -> message.contains(secretToken));
    }

    @Test
    void givenUnexpected403ResponseBody_whenCheckingPermission_thenTheAccessTokenIsNeverLogged() {
        String secretToken = "super-secret-access-token-value";
        server.expect(requestTo(TOKEN_URI))
                .andRespond(withForbiddenRequest()
                        .contentType(MediaType.APPLICATION_JSON)
                        .body("{\"error\":\"invalid_scope\",\"error_description\":\"unknown scope\"}"));

        client.isAllowed(request(jwtAuthentication(secretToken), Map.of("tenant", "tenant-a")));

        assertThat(logAppender.list)
                .extracting(ILoggingEvent::getFormattedMessage)
                .noneMatch(message -> message.contains(secretToken));
    }
}
