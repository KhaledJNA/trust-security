package com.trust.security.client;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * Matches requests eligible to be saved by {@code HttpSessionRequestCache} as
 * "the page to return to after login".
 * <p>
 * Spring Security's own default ({@code AnyRequestMatcher}) saves *every*
 * unauthenticated request that reaches the entry point - including a
 * same-origin {@code fetch()} session probe such as {@code GET /api/me},
 * which a single-page application typically issues on load to check whether
 * the user is already authenticated, with no intention of ever navigating
 * there. Left uncorrected, that probe gets replayed as the browser's actual
 * post-login destination instead of the application's own landing page
 * (or {@link OAuth2ClientSecurityProperties#getPostLoginRedirectUri()} when
 * configured), showing the probe's raw response instead of the SPA.
 * <p>
 * {@code Sec-Fetch-Mode} is a Fetch Metadata request header, set by the
 * browser itself - never readable or overridable by application script - on
 * every request it issues: {@code navigate} for an address-bar navigation, a
 * link click, or a form submission; {@code cors}, {@code same-origin} or
 * {@code no-cors} for {@code fetch()}/{@code XMLHttpRequest}. A request that
 * declares itself as anything other than {@code navigate} is never a page
 * the browser could usefully be redirected back to, so it is never saved. A
 * request with no such header at all (a client predating this header, or a
 * non-browser HTTP client) is saved, as by Spring Security's default - this
 * matcher only ever narrows what gets saved, never widens it.
 */
public final class NavigationRequestMatcher implements RequestMatcher {

    public static final NavigationRequestMatcher INSTANCE = new NavigationRequestMatcher();

    private static final String SEC_FETCH_MODE_HEADER = "Sec-Fetch-Mode";
    private static final String NAVIGATE = "navigate";

    private NavigationRequestMatcher() {
    }

    @Override
    public boolean matches(HttpServletRequest request) {
        String secFetchMode = request.getHeader(SEC_FETCH_MODE_HEADER);
        return secFetchMode == null || NAVIGATE.equalsIgnoreCase(secFetchMode);
    }
}
