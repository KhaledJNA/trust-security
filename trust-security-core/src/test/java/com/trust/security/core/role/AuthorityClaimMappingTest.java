package com.trust.security.core.role;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class AuthorityClaimMappingTest {

    @Test
    void givenValidPathAndPrefix_whenConstructing_thenValuesAreExposed() {
        AuthorityClaimMapping mapping = new AuthorityClaimMapping("permissions.roles", "ROLE_", null);

        assertThat(mapping.path()).isEqualTo("permissions.roles");
        assertThat(mapping.prefix()).isEqualTo("ROLE_");
    }

    @Test
    void givenThreeArgumentConstructorWithSeparator_whenConstructing_thenSeparatorIsExposed() {
        AuthorityClaimMapping mapping = new AuthorityClaimMapping("scope", "SCOPE_", " ");

        assertThat(mapping.separator()).isEqualTo(" ");
    }

    @Test
    void givenThreeArgumentConstructorWithNullSeparator_whenConstructing_thenNoExceptionIsThrown() {
        AuthorityClaimMapping mapping = new AuthorityClaimMapping("permissions.roles", "ROLE_", null);

        assertThat(mapping.separator()).isNull();
    }

    @Test
    void givenNullPath_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new AuthorityClaimMapping(null, "ROLE_", null));
    }

    @Test
    void givenNullPrefix_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new AuthorityClaimMapping("permissions.roles", null, null));
    }
}
