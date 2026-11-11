package com.trust.security.client;

import com.trust.security.client.authorities.ClaimGrantedAuthoritiesMapper;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import com.trust.security.core.user.CurrentAuthoritiesProvider;
import com.trust.security.core.user.CurrentUserProvider;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import tools.jackson.databind.ObjectMapper;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the wiring contract of {@link OAuth2ClientAutoConfiguration}
 * end-to-end (including the {@link SecurityFilterChain} bean, hence the
 * {@link WebApplicationContextRunner} rather than a plain one) - not Spring
 * Security's own DSL behavior, only what Trust configures on top of it.
 */
class OAuth2ClientAutoConfigurationTest {

    private static final String POST_LOGOUT_REDIRECT_URI_PROPERTY =
            "trust.security.post-logout-redirect-uri=http://127.0.0.1:8081/";

    private static ClientRegistration clientRegistration() {
        return clientRegistration("test-client");
    }

    private static ClientRegistration clientRegistration(String registrationId) {
        return ClientRegistration.withRegistrationId(registrationId)
                .clientId("my-app")
                .clientSecret("secret")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .authorizationUri("https://idp.example.com/auth")
                .tokenUri("https://idp.example.com/token")
                .userNameAttributeName("sub")
                .clientName(registrationId)
                .scope("openid")
                .build();
    }

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class))
            .withBean(ClientRegistrationRepository.class,
                    () -> new InMemoryClientRegistrationRepository(clientRegistration()))
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withPropertyValues(POST_LOGOUT_REDIRECT_URI_PROPERTY);

    @Test
    void givenRequiredCollaboratorsAndProperties_whenContextStarts_thenItLoadsSuccessfully() {
        contextRunner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void whenContextStarts_thenDefaultAuthoritiesAndUserBeansArePresent() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(ClaimAuthoritiesMapper.class);
            assertThat(context).hasSingleBean(GrantedAuthoritiesMapper.class);
            assertThat(context.getBean(GrantedAuthoritiesMapper.class))
                    .isInstanceOf(ClaimGrantedAuthoritiesMapper.class);
            assertThat(context).hasSingleBean(CurrentUserProvider.class);
            assertThat(context).hasSingleBean(CurrentAuthoritiesProvider.class);
        });
    }

    @Test
    void whenContextStarts_thenSecurityFilterChainIsCreated() {
        contextRunner.run(context -> assertThat(context).hasSingleBean(SecurityFilterChain.class));
    }

    @Test
    void givenAllowedOriginsConfigured_whenContextStarts_thenCorsConfigurationSourceReflectsThem() {
        contextRunner
                .withPropertyValues("trust.security.allowed-origins[0]=http://localhost:5173")
                .run(context -> {
                    CorsConfigurationSource source = context.getBean(CorsConfigurationSource.class);
                    org.springframework.mock.web.MockHttpServletRequest request =
                            new org.springframework.mock.web.MockHttpServletRequest();
                    CorsConfiguration configuration = source.getCorsConfiguration(request);

                    assertThat(configuration).isNotNull();
                    assertThat(configuration.getAllowedOrigins()).containsExactly("http://localhost:5173");
                    assertThat(configuration.getAllowCredentials()).isTrue();
                    assertThat(configuration.getAllowedMethods())
                            .containsExactlyInAnyOrder("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS");
                });
    }

    @Test
    void givenNoAllowedOriginsConfigured_whenContextStarts_thenNoOriginIsAllowedByDefault() {
        contextRunner.run(context -> {
            CorsConfigurationSource source = context.getBean(CorsConfigurationSource.class);
            CorsConfiguration configuration =
                    source.getCorsConfiguration(new org.springframework.mock.web.MockHttpServletRequest());

            assertThat(configuration).isNotNull();
            assertThat(configuration.getAllowedOrigins()).isNullOrEmpty();
        });
    }

    @Test
    void givenApplicationSuppliedCurrentUserProvider_whenContextStarts_thenTrustDefaultBacksOff() {
        CurrentUserProvider custom = java.util.Optional::empty;

        contextRunner
                .withBean(CurrentUserProvider.class, () -> custom)
                .run(context -> {
                    assertThat(context).hasSingleBean(CurrentUserProvider.class);
                    assertThat(context.getBean(CurrentUserProvider.class)).isSameAs(custom);
                });
    }

    @Test
    void givenApplicationSuppliedGrantedAuthoritiesMapper_whenContextStarts_thenTrustDefaultBacksOff() {
        GrantedAuthoritiesMapper custom = authorities -> authorities;

        contextRunner
                .withBean(GrantedAuthoritiesMapper.class, () -> custom)
                .run(context -> {
                    assertThat(context).hasSingleBean(GrantedAuthoritiesMapper.class);
                    assertThat(context.getBean(GrantedAuthoritiesMapper.class)).isSameAs(custom);
                });
    }

    /**
     * This starter alone, no cohabitation involved: an application using only
     * this starter and redefining its own {@code SecurityFilterChain} must
     * keep working - the cohabitation guard added to {@link OAuth2ClientAutoConfiguration}
     * triggers on the presence of the resource server starter's class, never
     * on the presence of a {@code SecurityFilterChain} bean.
     */
    @Test
    void givenApplicationSuppliedSecurityFilterChain_whenContextStarts_thenTrustDefaultBacksOff() {
        SecurityFilterChain custom = org.mockito.Mockito.mock(SecurityFilterChain.class);

        contextRunner
                .withBean(SecurityFilterChain.class, () -> custom)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context.getBean(SecurityFilterChain.class)).isSameAs(custom);
                });
    }


    // --- post-login redirect target (no saved request to replay) ---------------------------

    private static org.springframework.security.web.authentication.AuthenticationSuccessHandler
            successHandlerFrom(org.springframework.boot.test.context.assertj.AssertableWebApplicationContext context) {
        return context.getBean(
                "oauth2ClientAuthenticationSuccessHandler",
                org.springframework.security.web.authentication.AuthenticationSuccessHandler.class);
    }

    private static org.springframework.security.core.Authentication anyAuthentication() {
        return org.springframework.security.authentication.UsernamePasswordAuthenticationToken
                .authenticated("user", "password", java.util.List.of());
    }

    @Test
    void givenNoPostLoginRedirectUriConfigured_whenAuthenticatingWithNoSavedRequest_thenRedirectsToApplicationRoot() {
        contextRunner.run(context -> {
            var handler = successHandlerFrom(context);
            var request = new org.springframework.mock.web.MockHttpServletRequest();
            var response = new org.springframework.mock.web.MockHttpServletResponse();

            handler.onAuthenticationSuccess(request, response, anyAuthentication());

            assertThat(response.getRedirectedUrl()).isEqualTo("/");
        });
    }

    @Test
    void givenPostLoginRedirectUriConfigured_whenAuthenticatingWithNoSavedRequest_thenRedirectsThere() {
        contextRunner
                .withPropertyValues("trust.security.post-login-redirect-uri=http://localhost:5173/")
                .run(context -> {
                    var handler = successHandlerFrom(context);
                    var request = new org.springframework.mock.web.MockHttpServletRequest();
                    var response = new org.springframework.mock.web.MockHttpServletResponse();

                    handler.onAuthenticationSuccess(request, response, anyAuthentication());

                    assertThat(response.getRedirectedUrl()).isEqualTo("http://localhost:5173/");
                });
    }

    @Test
    void givenApplicationSuppliedSuccessHandler_whenContextStarts_thenTrustDefaultBacksOff() {
        org.springframework.security.web.authentication.AuthenticationSuccessHandler custom =
                (request, response, authentication) -> { };

        contextRunner
                .withBean("oauth2ClientAuthenticationSuccessHandler",
                        org.springframework.security.web.authentication.AuthenticationSuccessHandler.class,
                        () -> custom)
                .withPropertyValues("trust.security.post-login-redirect-uri=http://localhost:5173/")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(successHandlerFrom(context)).isSameAs(custom);
                });
    }

    // --- request cache (fetch/XHR session probes must never be saved as the post-login target) ---

    @Test
    void givenFetchSessionProbe_whenSaved_thenNotRetained() {
        contextRunner.run(context -> {
            var requestCache = context.getBean(org.springframework.security.web.savedrequest.RequestCache.class);
            var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/api/me");
            request.addHeader("Sec-Fetch-Mode", "cors");
            var response = new org.springframework.mock.web.MockHttpServletResponse();

            requestCache.saveRequest(request, response);

            assertThat(requestCache.getRequest(request, response)).isNull();
        });
    }

    @Test
    void givenRealNavigation_whenSaved_thenRetained() {
        contextRunner.run(context -> {
            var requestCache = context.getBean(org.springframework.security.web.savedrequest.RequestCache.class);
            var request = new org.springframework.mock.web.MockHttpServletRequest("GET", "/account");
            request.addHeader("Sec-Fetch-Mode", "navigate");
            var response = new org.springframework.mock.web.MockHttpServletResponse();

            requestCache.saveRequest(request, response);

            assertThat(requestCache.getRequest(request, response)).isNotNull();
        });
    }

    @Test
    void givenApplicationSuppliedRequestCache_whenContextStarts_thenTrustDefaultBacksOff() {
        org.springframework.security.web.savedrequest.RequestCache custom =
                new org.springframework.security.web.savedrequest.NullRequestCache();

        contextRunner
                .withBean("customRequestCache",
                        org.springframework.security.web.savedrequest.RequestCache.class,
                        () -> custom)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(org.springframework.security.web.savedrequest.RequestCache.class))
                            .isSameAs(custom);
                });
    }
}
