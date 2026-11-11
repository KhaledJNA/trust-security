package com.trust.security.client.tenant;

import com.trust.security.client.OAuth2ClientAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Drives real HTTP-shaped requests through the actual {@code SecurityFilterChain}
 * (via MockMvc, same pattern as the resource-server starter's wire-level
 * tests) to prove end-to-end wiring - not just bean presence.
 * {@code @EnableWebSecurity} on {@link OAuth2ClientAutoConfiguration} is
 * enough on its own to register {@code springSecurityFilterChain}, no Boot
 * web autoconfiguration needed - same reasoning as
 * {@code ResourceServerAutoConfigurationTest}'s sibling wire tests.
 */
class TenantLoginWireCharacterizationTest {

    private static final String POST_LOGOUT_REDIRECT_URI_PROPERTY =
            "trust.security.post-logout-redirect-uri=http://127.0.0.1:8081/";
    private static final String RESOLUTION_PREFIX =
            "trust.security.oauth2-client.login.registration-id-resolution";

    private static ClientRegistrationRepository twoTenantRegistrations() {
        return new InMemoryClientRegistrationRepository(
                org.springframework.security.oauth2.client.registration.ClientRegistration
                        .withRegistrationId("keycloak-acme")
                        .clientId("bff-acme")
                        .clientSecret("secret")
                        .authorizationGrantType(
                                org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                        .authorizationUri("https://idp-acme.example.com/auth")
                        .tokenUri("https://idp-acme.example.com/token")
                        .userNameAttributeName("sub")
                        .clientName("keycloak-acme")
                        .scope("openid")
                        .build(),
                org.springframework.security.oauth2.client.registration.ClientRegistration
                        .withRegistrationId("keycloak-globex")
                        .clientId("bff-globex")
                        .clientSecret("secret")
                        .authorizationGrantType(
                                org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                        .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                        .authorizationUri("https://idp-globex.example.com/auth")
                        .tokenUri("https://idp-globex.example.com/token")
                        .userNameAttributeName("sub")
                        .clientName("keycloak-globex")
                        .scope("openid")
                        .build());
    }

    private WebApplicationContextRunner baseRunner() {
        return new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class))
                .withBean(ClientRegistrationRepository.class, TenantLoginWireCharacterizationTest::twoTenantRegistrations)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(
                        POST_LOGOUT_REDIRECT_URI_PROPERTY,
                        RESOLUTION_PREFIX + ".request-pattern=/sso/login",
                        RESOLUTION_PREFIX + ".source=host",
                        RESOLUTION_PREFIX + ".mappings.acme.application.fr=keycloak-acme",
                        RESOLUTION_PREFIX + ".mappings.globex.application.fr=keycloak-globex");
    }

    private static MockMvc mockMvcFor(org.springframework.context.ApplicationContext context) {
        return MockMvcBuilders.webAppContextSetup((org.springframework.web.context.WebApplicationContext) context)
                .apply(springSecurity())
                .build();
    }

    /**
     * {@code MockHttpServletRequest.getServerName()} is set from the URL
     * passed to the request builder, never from a raw {@code Host} header
     * added afterwards - an absolute URL is required here for the same
     * reason a real servlet container derives {@code getServerName()} from
     * the connection/{@code Host} header rather than from a header value the
     * application could set itself.
     */
    @Test
    void givenKnownHost_whenCallingTheTenantLoginPath_thenRedirectsToTheMatchingOAuth2AuthorizationEndpoint() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);

            mockMvc.perform(get("http://acme.application.fr/sso/login"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(header().string("Location", "/oauth2/authorization/keycloak-acme"));
        });
    }

    @Test
    void givenUnknownHost_whenCallingTheTenantLoginPath_thenRejectedWithProblemDetailsNotFound() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);

            mockMvc.perform(get("http://unknown.application.fr/sso/login"))
                    .andExpect(status().isNotFound())
                    .andExpect(result -> assertThat(result.getResponse().getContentType())
                            .startsWith("application/problem+json"));
        });
    }

    /**
     * Direct access to Spring's own standard URL must never be touched by the
     * new filter - it never matches {@code /oauth2/authorization/**}, so this
     * request is only ever handled by {@code OAuth2AuthorizationRequestRedirectFilter}
     * itself, exactly as without this feature.
     */
    @Test
    void givenDirectAccessToStandardOAuth2AuthorizationEndpoint_whenCalled_thenBehaviorIsUnchanged() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);

            mockMvc.perform(get("/oauth2/authorization/keycloak-acme"))
                    .andExpect(status().is3xxRedirection())
                    .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl())
                            .startsWith("https://idp-acme.example.com/auth"));
        });
    }

    /**
     * A request outside the configured {@code request-pattern} is never
     * intercepted by the new filter - it never produces this filter's own
     * 404/Problem Details rejection, regardless of whatever Spring Security's
     * own unauthenticated-access handling ends up doing with it.
     */
    @Test
    void givenRequestOutsideTheConfiguredPattern_whenCalled_thenNeverInterceptedByTheNewFilter() {
        baseRunner().run(context -> {
            MockMvc mockMvc = mockMvcFor(context);

            org.springframework.test.web.servlet.MvcResult result =
                    mockMvc.perform(get("/unrelated/path")).andReturn();

            assertThat(result.getResponse().getStatus()).isNotEqualTo(404);
        });
    }

    /**
     * Non-regression: a single-registration ("mono-tenant") application with
     * no {@code registration-id-resolution} configured keeps working exactly
     * as it does today.
     */
    @Test
    void givenNoRegistrationIdResolutionConfigured_whenAccessingStandardOAuth2AuthorizationEndpoint_thenUnaffected() {
        new WebApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(OAuth2ClientAutoConfiguration.class))
                .withBean(ClientRegistrationRepository.class, () -> new InMemoryClientRegistrationRepository(
                        org.springframework.security.oauth2.client.registration.ClientRegistration
                                .withRegistrationId("keycloak")
                                .clientId("bff")
                                .clientSecret("secret")
                                .authorizationGrantType(
                                        org.springframework.security.oauth2.core.AuthorizationGrantType.AUTHORIZATION_CODE)
                                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                                .authorizationUri("https://idp.example.com/auth")
                                .tokenUri("https://idp.example.com/token")
                                .userNameAttributeName("sub")
                                .clientName("keycloak")
                                .scope("openid")
                                .build()))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(POST_LOGOUT_REDIRECT_URI_PROPERTY)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(TenantLoginRequestFilter.class);

                    MockMvc mockMvc = mockMvcFor(context);
                    mockMvc.perform(get("/oauth2/authorization/keycloak"))
                            .andExpect(status().is3xxRedirection())
                            .andExpect(result -> assertThat(result.getResponse().getRedirectedUrl())
                                    .startsWith("https://idp.example.com/auth"));
                });
    }
}
