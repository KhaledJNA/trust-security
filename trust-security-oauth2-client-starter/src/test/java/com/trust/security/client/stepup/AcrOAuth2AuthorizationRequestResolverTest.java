package com.trust.security.client.stepup;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

/**
 * Behavioral tests for {@link AcrOAuth2AuthorizationRequestResolver}. Verifies
 * only what Trust adds (the {@code acr_values} passthrough) on top of the
 * standard {@code DefaultOAuth2AuthorizationRequestResolver} delegate -
 * not Spring Security's own resolution logic.
 */
class AcrOAuth2AuthorizationRequestResolverTest {

    private static ClientRegistration clientRegistration() {
        return ClientRegistration.withRegistrationId("test-client")
                .clientId("my-app")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://idp.example.com/auth")
                .tokenUri("https://idp.example.com/token")
                .userNameAttributeName("sub")
                .clientName("test-client")
                .scope("openid")
                .build();
    }

    private static ClientRegistrationRepository repository() {
        return new InMemoryClientRegistrationRepository(clientRegistration());
    }

    @Test
    void givenNullClientRegistrationRepository_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new AcrOAuth2AuthorizationRequestResolver(null));
    }

    @Test
    void givenRequestWithoutAcrValues_whenResolvingByPath_thenDelegateRequestIsReturnedUnchanged() {
        AcrOAuth2AuthorizationRequestResolver resolver =
                new AcrOAuth2AuthorizationRequestResolver(repository());
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", "/oauth2/authorization/test-client");
        request.setServletPath("/oauth2/authorization/test-client");

        OAuth2AuthorizationRequest resolved = resolver.resolve(request);

        assertThat(resolved).isNotNull();
        assertThat(resolved.getAdditionalParameters()).doesNotContainKey("acr_values");
    }

    @Test
    void givenRequestWithAcrValues_whenResolvingByPath_thenAcrValuesIsAddedToAdditionalParameters() {
        AcrOAuth2AuthorizationRequestResolver resolver =
                new AcrOAuth2AuthorizationRequestResolver(repository());
        MockHttpServletRequest request = new MockHttpServletRequest(
                "GET", "/oauth2/authorization/test-client");
        request.setServletPath("/oauth2/authorization/test-client");
        request.addParameter("acr_values", "urn:acr:mfa");

        OAuth2AuthorizationRequest resolved = resolver.resolve(request);

        assertThat(resolved).isNotNull();
        assertThat(resolved.getAdditionalParameters()).containsEntry("acr_values", "urn:acr:mfa");
    }

    @Test
    void givenRequestWithAcrValues_whenResolvingByExplicitRegistrationId_thenAcrValuesIsAddedToAdditionalParameters() {
        AcrOAuth2AuthorizationRequestResolver resolver =
                new AcrOAuth2AuthorizationRequestResolver(repository());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/anything");
        request.addParameter("acr_values", "urn:acr:mfa");

        OAuth2AuthorizationRequest resolved = resolver.resolve(request, "test-client");

        assertThat(resolved).isNotNull();
        assertThat(resolved.getAdditionalParameters()).containsEntry("acr_values", "urn:acr:mfa");
    }

    @Test
    void givenNonMatchingPath_whenResolvingByPath_thenDelegateReturnsNullWithoutException() {
        AcrOAuth2AuthorizationRequestResolver resolver =
                new AcrOAuth2AuthorizationRequestResolver(repository());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/unrelated/path");
        request.setServletPath("/unrelated/path");

        OAuth2AuthorizationRequest resolved = resolver.resolve(request);

        assertThat(resolved).isNull();
    }

    /**
     * The delegate's own exception type ({@code InvalidClientRegistrationIdException})
     * is package-private in spring-security-oauth2-client, so it is asserted
     * here via its public superclass.
     */
    @Test
    void givenUnknownRegistrationId_whenResolvingByExplicitRegistrationId_thenDelegateExceptionPropagates() {
        AcrOAuth2AuthorizationRequestResolver resolver =
                new AcrOAuth2AuthorizationRequestResolver(repository());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/anything");

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> resolver.resolve(request, "unknown-client"));
    }

    @Test
    void givenNullRegistrationId_whenResolvingByExplicitRegistrationId_thenNullIsReturned() {
        AcrOAuth2AuthorizationRequestResolver resolver =
                new AcrOAuth2AuthorizationRequestResolver(repository());
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/anything");

        OAuth2AuthorizationRequest resolved = resolver.resolve(request, null);

        assertThat(resolved).isNull();
    }
}
