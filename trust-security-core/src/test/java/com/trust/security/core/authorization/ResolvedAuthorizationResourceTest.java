package com.trust.security.core.authorization;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class ResolvedAuthorizationResourceTest {

    static class StubProvider implements PermissionContextProvider {
        @Override
        public Map<String, String> resolve(Object resourceId) {
            return Map.of();
        }
    }

    @Test
    void givenValidIdAndProviderType_whenConstructing_thenValuesAreExposed() {
        ResolvedAuthorizationResource resource =
                new ResolvedAuthorizationResource("order-42", StubProvider.class);

        assertThat(resource.id()).isEqualTo("order-42");
        assertThat(resource.contextProviderType()).isEqualTo(StubProvider.class);
    }

    @Test
    void givenNullId_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new ResolvedAuthorizationResource(null, StubProvider.class));
    }

    @Test
    void givenNullProviderType_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new ResolvedAuthorizationResource("order-42", null));
    }
}
