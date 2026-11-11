package com.trust.security.core.authorization;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class AuthorizationRequestTest {

    @Test
    void givenValidValues_whenConstructing_thenAllValuesAreExposed() {
        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", java.util.List.of());
        Map<String, String> context = Map.of("tenant", "tenant-a");

        AuthorizationRequest request =
                new AuthorizationRequest(authentication, "Document", "modify", context);

        assertThat(request.authentication()).isSameAs(authentication);
        assertThat(request.resource()).isEqualTo("Document");
        assertThat(request.action()).isEqualTo("modify");
        assertThat(request.context()).isEqualTo(context);
    }

    @Test
    void givenNullContext_whenConstructing_thenContextIsNormalizedToEmptyMap() {
        AuthorizationRequest request =
                new AuthorizationRequest(null, "Document", "modify", null);

        assertThat(request.context()).isEmpty();
    }

    @Test
    void givenNullAuthentication_whenConstructing_thenNoExceptionIsThrown() {
        AuthorizationRequest request =
                new AuthorizationRequest(null, "Document", "modify", Map.of());

        assertThat(request.authentication()).isNull();
    }

    @Test
    void givenNullResource_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new AuthorizationRequest(null, null, "modify", Map.of()));
    }

    @Test
    void givenNullAction_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new AuthorizationRequest(null, "Document", null, Map.of()));
    }
}
