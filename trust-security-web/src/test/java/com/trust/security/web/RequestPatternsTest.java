package com.trust.security.web;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class RequestPatternsTest {

    @ParameterizedTest
    @CsvSource({
            "/app/**, /app/**",
            "/app/**, /app",
            "/app/**, /app/admin/**",
            "/app/, /app/**",
            "/**, /api/**",
            "/api/**, /**",
            "/oauth2/authorization/extra, /oauth2/authorization",
            "/api/*, /api/documents",
            "/api/*/admin, /api/v1/**",
            "/{tenant}/login, /acme/**",
            "/oauth2/{action}/x, /oauth2/authorization",
            "/app/**/admin, /app/v1/users",
            "/app//admin, /app/admin",
    })
    void givenPatternsSharingAPrefix_thenTheyOverlap(String a, String b) {
        assertThat(RequestPatterns.overlap(a, b)).isTrue();
        assertThat(RequestPatterns.overlap(b, a)).isTrue();
    }

    @ParameterizedTest
    @CsvSource({
            "/app/**, /api/**",
            "/app/**, /application/**",
            "/sso/login, /logout",
            "/sso/login/{tenant}, /oauth2/authorization",
            "/{tenant}/login, /acme/logout",
            "/api/*, /app/documents",
    })
    void givenDisjointPatterns_thenTheyDoNotOverlap(String a, String b) {
        assertThat(RequestPatterns.overlap(a, b)).isFalse();
        assertThat(RequestPatterns.overlap(b, a)).isFalse();
    }
}
