package com.trust.restclient;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.mock.http.client.MockClientHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

class ResourceServerTokenRelayInterceptorTest {

    private final ResourceServerTokenRelayInterceptor interceptor = new ResourceServerTokenRelayInterceptor();

    private static JwtAuthenticationToken jwtAuthentication(String tokenValue) {
        Jwt jwt = Jwt.withTokenValue(tokenValue)
                .header("alg", "none")
                .claim("sub", "user-1")
                .issuedAt(Instant.EPOCH)
                .expiresAt(Instant.EPOCH.plusSeconds(3600))
                .build();
        return new JwtAuthenticationToken(jwt);
    }

    private static BearerTokenAuthentication opaqueAuthentication(String tokenValue) {
        OAuth2AuthenticatedPrincipal principal =
                new DefaultOAuth2AuthenticatedPrincipal("user-1", Map.of("sub", "user-1"), List.of());
        OAuth2AccessToken accessToken = new OAuth2AccessToken(
                OAuth2AccessToken.TokenType.BEARER, tokenValue, Instant.EPOCH, Instant.EPOCH.plusSeconds(3600));
        return new BearerTokenAuthentication(principal, accessToken, List.of());
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void givenJwtAuthenticationInSecurityContext_whenIntercepting_thenBearerTokenIsRelayed() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication("the-access-token"));
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        given(execution.execute(request, body)).willReturn(response);

        ClientHttpResponse result = interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().getFirst("Authorization")).isEqualTo("Bearer the-access-token");
        assertThat(result).isSameAs(response);
    }

    @Test
    void givenNoAuthenticationInSecurityContext_whenIntercepting_thenNoAuthorizationHeaderIsAdded() throws Exception {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().containsHeader("Authorization")).isFalse();
    }

    @Test
    void givenNonJwtAuthenticationInSecurityContext_whenIntercepting_thenNoAuthorizationHeaderIsAdded() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of()));
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().containsHeader("Authorization")).isFalse();
    }

    @Test
    void givenRequestAlreadyHasAnAuthorizationHeader_whenIntercepting_thenTheRelayedTokenReplacesIt() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication("the-access-token"));
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        request.getHeaders().set("Authorization", "Basic stale-credentials");
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().get("Authorization")).containsExactly("Bearer the-access-token");
    }

    @Test
    void whenIntercepting_thenTheRequestIsExecutedExactlyOnce() throws Exception {
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        verify(execution, times(1)).execute(request, body);
    }

    @Test
    void givenOpaqueAuthenticationInSecurityContext_whenIntercepting_thenBearerTokenIsRelayed() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(opaqueAuthentication("the-opaque-token"));
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        ClientHttpResponse response = mock(ClientHttpResponse.class);
        given(execution.execute(request, body)).willReturn(response);

        ClientHttpResponse result = interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().getFirst("Authorization")).isEqualTo("Bearer the-opaque-token");
        assertThat(result).isSameAs(response);
    }

    /**
     * Simulates what {@code NoTokenRelayProcessor} would have posed on the
     * request attribute for a {@code @NoTokenRelay}-annotated call - the
     * processor itself is covered by {@code NoTokenRelayProcessorTest}.
     */
    @Test
    void givenNoTokenRelayAttributeSet_whenIntercepting_thenNoAuthorizationHeaderIsAddedEvenWithValidAuthentication()
            throws Exception {
        SecurityContextHolder.getContext().setAuthentication(jwtAuthentication("the-access-token"));
        MockClientHttpRequest request = new MockClientHttpRequest(HttpMethod.GET, URI.create("http://api.example.com/ping"));
        request.getAttributes().put(
                "com.trust.restclient.tokenrelay.NoTokenRelayProcessor.NO_TOKEN_RELAY", Boolean.TRUE);
        byte[] body = new byte[0];
        ClientHttpRequestExecution execution = mock(ClientHttpRequestExecution.class);
        given(execution.execute(request, body)).willReturn(mock(ClientHttpResponse.class));

        interceptor.intercept(request, body, execution);

        assertThat(request.getHeaders().containsHeader("Authorization")).isFalse();
    }
}
