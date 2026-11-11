package com.trust.security.client;

import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;

import static org.assertj.core.api.Assertions.assertThat;

class SessionCookieClearingLogoutHandlerTest {

    private final SessionCookieClearingLogoutHandler handler = new SessionCookieClearingLogoutHandler();

    @Test
    void givenDefaultSessionCookieName_whenLoggingOut_thenJsessionidIsExpired() {
        MockHttpServletRequest request = new MockHttpServletRequest(new MockServletContext());
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.logout(request, response, null);

        Cookie cookie = response.getCookie("JSESSIONID");
        assertThat(cookie).isNotNull();
        assertThat(cookie.getMaxAge()).isZero();
    }

    @Test
    void givenRenamedSessionCookie_whenLoggingOut_thenThatCookieIsExpired() {
        MockServletContext servletContext = new MockServletContext();
        servletContext.getSessionCookieConfig().setName("BFF_SESSION");
        MockHttpServletRequest request = new MockHttpServletRequest(servletContext);
        MockHttpServletResponse response = new MockHttpServletResponse();

        handler.logout(request, response, null);

        assertThat(response.getCookie("BFF_SESSION")).isNotNull();
        assertThat(response.getCookie("BFF_SESSION").getMaxAge()).isZero();
        assertThat(response.getCookie("JSESSIONID")).isNull();
    }
}
