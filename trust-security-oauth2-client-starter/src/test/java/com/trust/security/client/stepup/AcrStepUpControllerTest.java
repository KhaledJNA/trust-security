package com.trust.security.client.stepup;

import jakarta.servlet.http.HttpSession;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Behavioral tests for {@link AcrStepUpController}. Constructs it directly
 * and calls its handler method as a plain Java method - no need for a full
 * Spring MVC dispatch to verify its own validation and redirect logic.
 */
class AcrStepUpControllerTest {

    private final AcrStepUpController controller = new AcrStepUpController();

    private static OAuth2AuthenticationToken authentication(String registrationId) {
        OAuth2User principal = new DefaultOAuth2User(
                List.of(new SimpleGrantedAuthority("OIDC_USER")),
                Map.of("sub", "user-1"),
                "sub");
        return new OAuth2AuthenticationToken(principal, principal.getAuthorities(), registrationId);
    }

    @Test
    void givenValidAcrAndLocalReturnTo_whenSteppingUp_thenRedirectsToAuthorizationEndpointWithAcrValuesAndStoresReturnToInSession() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        String view = controller.stepUp("urn:acr:mfa", "/documents/42", authentication("test-client"), session);

        assertThat(view).isEqualTo("redirect:/oauth2/authorization/test-client?acr_values=urn%3Aacr%3Amfa");
        assertThat(session.getAttribute(AcrStepUpController.STEP_UP_RETURN_TO)).isEqualTo("/documents/42");
    }

    @Test
    void givenReturnToStartingWithDoubleSlash_whenSteppingUp_thenIllegalArgumentExceptionIsThrown() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> controller.stepUp("urn:acr:mfa", "//evil.example.com", authentication("test-client"), session))
                .withMessage("returnTo must be a local application path");
    }

    @Test
    void givenExternalAbsoluteReturnTo_whenSteppingUp_thenIllegalArgumentExceptionIsThrown() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> controller.stepUp("urn:acr:mfa", "http://evil.example.com", authentication("test-client"), session))
                .withMessage("returnTo must be a local application path");
    }

    @ParameterizedTest
    @ValueSource(strings = {"/\\evil.example.com", "/\t/evil.example.com", "/\n/evil.example.com"})
    void givenReturnToThatBrowsersNormalizeToProtocolRelative_whenSteppingUp_thenIllegalArgumentExceptionIsThrown(String returnTo) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> controller.stepUp("urn:acr:mfa", returnTo, authentication("test-client"), session))
                .withMessage("returnTo must be a local application path");
    }

    @Test
    void givenNullReturnTo_whenSteppingUp_thenIllegalArgumentExceptionIsThrown() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> controller.stepUp("urn:acr:mfa", null, authentication("test-client"), session))
                .withMessage("returnTo must be a local application path");
    }

    @Test
    void givenBlankAcr_whenSteppingUp_thenIllegalArgumentExceptionIsThrown() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> controller.stepUp("   ", "/documents/42", authentication("test-client"), session))
                .withMessage("acr must not be blank");
    }

    @Test
    void givenNullAcr_whenSteppingUp_thenIllegalArgumentExceptionIsThrown() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        assertThatExceptionOfType(IllegalArgumentException.class)
                .isThrownBy(() -> controller.stepUp(null, "/documents/42", authentication("test-client"), session))
                .withMessage("acr must not be blank");
    }

    @Test
    void givenAcrValueRequiringUrlEncoding_whenSteppingUp_thenItIsProperlyEncodedInTheRedirect() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        String view = controller.stepUp("urn:acr:mfa level2", "/documents/42", authentication("test-client"), session);

        assertThat(view).isEqualTo("redirect:/oauth2/authorization/test-client?acr_values=urn%3Aacr%3Amfa+level2");
    }

    /**
     * A non-OAuth2 {@link Authentication}
     * reaching this endpoint (e.g. an application combining {@code oauth2Login()}
     * with another authentication mechanism of its own) is rejected cleanly
     * through the same {@link AccessDeniedException} path as every other
     * authorization failure in this starter, rather than surfacing as a raw
     * {@code IllegalStateException}/{@code NullPointerException}.
     */
    @Test
    void givenNonOAuth2Authentication_whenSteppingUp_thenAccessDeniedExceptionIsThrown() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);
        var authentication = UsernamePasswordAuthenticationToken.authenticated(
                "user-1", "credentials", List.of(new SimpleGrantedAuthority("ROLE_USER")));

        assertThatExceptionOfType(AccessDeniedException.class)
                .isThrownBy(() -> controller.stepUp("urn:acr:mfa", "/documents/42", authentication, session));
    }

    @Test
    void givenNullAuthentication_whenSteppingUp_thenAccessDeniedExceptionIsThrown() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        HttpSession session = request.getSession(true);

        assertThatExceptionOfType(AccessDeniedException.class)
                .isThrownBy(() -> controller.stepUp("urn:acr:mfa", "/documents/42", null, session));
    }
}
