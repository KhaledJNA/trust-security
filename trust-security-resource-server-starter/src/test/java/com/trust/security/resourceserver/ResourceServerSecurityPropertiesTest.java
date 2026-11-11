package com.trust.security.resourceserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.context.properties.bind.validation.BindValidationException;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

class ResourceServerSecurityPropertiesTest {

    @Configuration
    @EnableConfigurationProperties(ResourceServerSecurityProperties.class)
    static class TestConfig {
    }

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner().withUserConfiguration(TestConfig.class);

    @Test
    void givenClientIdConfigured_whenBinding_thenPublicPathsDefaultsToEmpty() {
        contextRunner
                .withPropertyValues("trust.security.resource-server.client-id=sample-api")
                .run(context -> {
                    ResourceServerSecurityProperties properties =
                            context.getBean(ResourceServerSecurityProperties.class);
                    assertThat(properties.getClientId()).isEqualTo("sample-api");
                    assertThat(properties.getPublicPaths()).isEmpty();
                });
    }

    @Test
    void givenPublicPathsConfigured_whenBinding_thenTheyAreBound() {
        contextRunner
                .withPropertyValues(
                        "trust.security.resource-server.client-id=sample-api",
                        "trust.security.resource-server.public-paths[0]=/public/ping")
                .run(context -> {
                    ResourceServerSecurityProperties properties =
                            context.getBean(ResourceServerSecurityProperties.class);
                    assertThat(properties.getPublicPaths()).containsExactly("/public/ping");
                });
    }

    @Test
    void givenMissingClientId_whenBinding_thenContextFailsToStart() {
        contextRunner.run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure())
                    .hasRootCauseInstanceOf(BindValidationException.class);
        });
    }

    @Test
    void givenNoIssuersConfigured_whenBinding_thenIssuersDefaultsToEmpty() {
        contextRunner
                .withPropertyValues("trust.security.resource-server.client-id=sample-api")
                .run(context -> {
                    ResourceServerSecurityProperties properties =
                            context.getBean(ResourceServerSecurityProperties.class);
                    assertThat(properties.getIssuers()).isEmpty();
                });
    }

    @Test
    void givenIssuersConfigured_whenBinding_thenTheyAreBound() {
        contextRunner
                .withPropertyValues(
                        "trust.security.resource-server.client-id=sample-api",
                        "trust.security.resource-server.issuers[0].issuer-uri=https://idp-a.example.com/realms/trust",
                        "trust.security.resource-server.issuers[1].issuer-uri=https://idp-b.example.com/realms/partner",
                        "trust.security.resource-server.issuers[1].audience=sample-api-partner",
                        "trust.security.resource-server.issuers[1].jwk-set-uri=https://idp-b.example.com/certs")
                .run(context -> {
                    ResourceServerSecurityProperties properties =
                            context.getBean(ResourceServerSecurityProperties.class);
                    assertThat(properties.getIssuers()).hasSize(2);
                    assertThat(properties.getIssuers().get(0).getIssuerUri())
                            .isEqualTo("https://idp-a.example.com/realms/trust");
                    assertThat(properties.getIssuers().get(0).getAudience()).isNull();
                    assertThat(properties.getIssuers().get(1).getAudience()).isEqualTo("sample-api-partner");
                    assertThat(properties.getIssuers().get(1).getJwkSetUri())
                            .isEqualTo("https://idp-b.example.com/certs");
                });
    }

    @Test
    void givenAnIssuerEntryWithoutIssuerUri_whenBinding_thenContextFailsToStart() {
        contextRunner
                .withPropertyValues(
                        "trust.security.resource-server.client-id=sample-api",
                        "trust.security.resource-server.issuers[0].audience=sample-api")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .hasRootCauseInstanceOf(BindValidationException.class);
                });
    }
}
