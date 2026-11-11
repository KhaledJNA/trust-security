package com.trust.security.client.stepup;

import jakarta.servlet.http.HttpSession;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@Controller
public final class AcrStepUpController {

    public static final String STEP_UP_RETURN_TO =
            AcrStepUpController.class.getName() + ".RETURN_TO";

    /**
     * The {@code authentication} parameter is deliberately typed as the
     * generic {@link Authentication}, not {@link OAuth2AuthenticationToken}
     * : this starter refuses, at startup, to cohabit with
     * {@code trust-security-resource-server-starter} without multi-chain
     * mode, the usual way a non-OAuth2 authentication would reach this
     * endpoint - but that guard does not make this
     * defensive check redundant. An application using only this starter
     * remains free to add another authentication mechanism of its own
     * alongside {@code oauth2Login()} (e.g. HTTP Basic for an older client),
     * and nothing stops such a request from reaching this endpoint too. A
     * strict {@link OAuth2AuthenticationToken} parameter would let Spring's
     * own generic type-checking argument resolver fail with a raw
     * {@code IllegalStateException} (a plain 500, breaking the RFC 9457
     * Problem Details format this starter uses everywhere else); checking
     * explicitly and throwing {@link AccessDeniedException} routes the
     * failure through the same {@code AccessDeniedHandler} as every other
     * authorization failure in this starter.
     */
    @GetMapping("/oauth2/step-up")
    public String stepUp(
            @RequestParam("acr") String acr,
            @RequestParam("returnTo") String returnTo,
            Authentication authentication,
            HttpSession session) {

        validateAcr(acr);
        validateReturnTo(returnTo);

        if (!(authentication instanceof OAuth2AuthenticationToken oauth2Authentication)) {
            throw new AccessDeniedException(
                    "Step-up authentication requires an active OAuth2 login session; "
                            + "the current authentication is not an OAuth2AuthenticationToken."
            );
        }

        session.setAttribute(STEP_UP_RETURN_TO, returnTo);

        String registrationId =
                oauth2Authentication.getAuthorizedClientRegistrationId();

        return "redirect:/oauth2/authorization/"
                + registrationId
                + "?acr_values="
                + URLEncoder.encode(acr, StandardCharsets.UTF_8);
    }

    private void validateAcr(String acr) {
        if (acr == null || acr.isBlank()) {
            throw new InvalidStepUpRequestException(
                    "acr must not be blank"
            );
        }
    }

    /**
     * Only a path on this application is accepted. Browsers read {@code \}
     * as {@code /} and drop tabs/newlines from URLs, so {@code /\evil.com} or
     * {@code /<TAB>/evil.com} would otherwise become {@code //evil.com}: an
     * open redirect.
     */
    private void validateReturnTo(String returnTo) {
        if (returnTo == null
                || !returnTo.startsWith("/")
                || returnTo.startsWith("//")
                || returnTo.indexOf('\\') >= 0
                || returnTo.chars().anyMatch(Character::isISOControl)) {

            throw new InvalidStepUpRequestException(
                    "returnTo must be a local application path"
            );
        }
    }
}