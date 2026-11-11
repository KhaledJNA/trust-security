package com.trust.security.client.stepup;

import org.junit.jupiter.api.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * HTTP status of {@code /oauth2/step-up} through Spring MVC: an invalid input
 * is a 400, not a 500.
 */
class AcrStepUpControllerHttpTest {

    private final MockMvc mockMvc = MockMvcBuilders.standaloneSetup(new AcrStepUpController()).build();

    private static OAuth2AuthenticationToken authentication() {
        OAuth2User principal = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("OIDC_USER")), Map.of("sub", "user-1"), "sub");
        return new OAuth2AuthenticationToken(principal, principal.getAuthorities(), "test-client");
    }

    @Test
    void givenValidRequest_thenRedirectsToAuthorizationEndpoint() throws Exception {
        mockMvc.perform(get("/oauth2/step-up")
                        .param("acr", "mfa")
                        .param("returnTo", "/documents/42")
                        .principal(authentication()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/oauth2/authorization/test-client?acr_values=mfa"));
    }

    @Test
    void givenExternalReturnTo_thenBadRequest() throws Exception {
        mockMvc.perform(get("/oauth2/step-up")
                        .param("acr", "mfa")
                        .param("returnTo", "//evil.example.com")
                        .principal(authentication()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void givenBlankAcr_thenBadRequest() throws Exception {
        mockMvc.perform(get("/oauth2/step-up")
                        .param("acr", " ")
                        .param("returnTo", "/documents/42")
                        .principal(authentication()))
                .andExpect(status().isBadRequest());
    }
}
