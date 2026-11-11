package com.trust.security.client;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class OAuth2ClientSecurityPropertiesTest {

    private static final String VALID_POST_LOGOUT_REDIRECT_URI =
            "trust.security.post-logout-redirect-uri=http://127.0.0.1:8081/";

    @Configuration
    @EnableConfigurationProperties(OAuth2ClientSecurityProperties.class)
    static class TestConfig {
    }

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner().withUserConfiguration(TestConfig.class);

    @Test
    void givenOnlyRequiredPropertiesConfigured_whenBinding_thenDefaultsApply() {
        contextRunner
                .withPropertyValues(VALID_POST_LOGOUT_REDIRECT_URI)
                .run(context -> {
                    OAuth2ClientSecurityProperties properties = context.getBean(OAuth2ClientSecurityProperties.class);
                    assertThat(properties.getAllowedOrigins()).isEmpty();
                    assertThat(properties.getPublicPaths()).isEmpty();
                    assertThat(properties.getLogoutPath()).isEqualTo("/logout");
                    assertThat(properties.getPostLoginRedirectUri()).isNull();
                });
    }

    @Test
    void givenPostLoginRedirectUriConfigured_whenBinding_thenItIsBound() {
        contextRunner
                .withPropertyValues(
                        VALID_POST_LOGOUT_REDIRECT_URI,
                        "trust.security.post-login-redirect-uri=http://localhost:5173/")
                .run(context -> {
                    OAuth2ClientSecurityProperties properties = context.getBean(OAuth2ClientSecurityProperties.class);
                    assertThat(properties.getPostLoginRedirectUri()).isEqualTo("http://localhost:5173/");
                });
    }

    @Test
    void givenAllowedOriginsAndPublicPathsConfigured_whenBinding_thenTheyAreBound() {
        contextRunner
                .withPropertyValues(
                        VALID_POST_LOGOUT_REDIRECT_URI,
                        "trust.security.allowed-origins[0]=http://localhost:5173",
                        "trust.security.public-paths[0]=/js/**")
                .run(context -> {
                    OAuth2ClientSecurityProperties properties = context.getBean(OAuth2ClientSecurityProperties.class);
                    assertThat(properties.getAllowedOrigins()).containsExactly("http://localhost:5173");
                    assertThat(properties.getPublicPaths()).containsExactly("/js/**");
                });
    }

    @Test
    void givenCustomLogoutPathConfigured_whenBinding_thenItReplacesTheDefault() {
        contextRunner
                .withPropertyValues(VALID_POST_LOGOUT_REDIRECT_URI, "trust.security.logout-path=/api/logout")
                .run(context -> {
                    OAuth2ClientSecurityProperties properties = context.getBean(OAuth2ClientSecurityProperties.class);
                    assertThat(properties.getLogoutPath()).isEqualTo("/api/logout");
                });
    }

    @Test
    void givenMissingPostLogoutRedirectUri_whenBinding_thenContextFailsToStart() {
        contextRunner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasRootCauseInstanceOf(BindValidationException.class);
        });
    }

    @Test
    void givenAllowedOriginWithoutScheme_whenBinding_thenContextFailsToStart() {
        contextRunner
                .withPropertyValues(
                        VALID_POST_LOGOUT_REDIRECT_URI,
                        "trust.security.allowed-origins[0]=exemple.fr")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class);
                });
    }
}
