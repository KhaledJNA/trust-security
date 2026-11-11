package com.trust.security.client;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class NavigationRequestMatcherTest {

    @Test
    void givenNoSecFetchModeHeader_whenMatching_thenMatches() {
        MockHttpServletRequest request = new MockHttpServletRequest();

        assertThat(NavigationRequestMatcher.INSTANCE.matches(request)).isTrue();
    }

    @Test
    void givenSecFetchModeNavigate_whenMatching_thenMatches() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Sec-Fetch-Mode", "navigate");

        assertThat(NavigationRequestMatcher.INSTANCE.matches(request)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {"cors", "same-origin", "no-cors", "websocket"})
    void givenNonNavigateSecFetchMode_whenMatching_thenDoesNotMatch(String secFetchMode) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Sec-Fetch-Mode", secFetchMode);

        assertThat(NavigationRequestMatcher.INSTANCE.matches(request)).isFalse();
    }
}
