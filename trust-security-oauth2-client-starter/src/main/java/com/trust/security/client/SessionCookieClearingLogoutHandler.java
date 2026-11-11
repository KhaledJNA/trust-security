package com.trust.security.client;

import jakarta.servlet.SessionCookieConfig;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.CookieClearingLogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.util.StringUtils;

/**
 * Expires the session cookie on logout, under the name the servlet container
 * actually uses - {@code server.servlet.session.cookie.name} when the
 * application sets it, {@code JSESSIONID} otherwise. A hardcoded
 * {@code JSESSIONID} would leave a renamed cookie in the browser.
 */
final class SessionCookieClearingLogoutHandler implements LogoutHandler {

    static final String DEFAULT_SESSION_COOKIE_NAME = "JSESSIONID";

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        new CookieClearingLogoutHandler(sessionCookieName(request)).logout(request, response, authentication);
    }

    private static String sessionCookieName(HttpServletRequest request) {
        SessionCookieConfig config = request.getServletContext().getSessionCookieConfig();
        String name = config == null ? null : config.getName();
        return StringUtils.hasText(name) ? name : DEFAULT_SESSION_COOKIE_NAME;
    }
}
