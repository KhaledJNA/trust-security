package com.trust.security.resourceserver;

import com.trust.security.core.role.AuthorityClaimMapping;
import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that the application-facing {@code trust.security.authorities.mappings}
 * configuration is actually bound onto {@link AuthorityClaimMapping} instances -
 * the contract the rest of the starter (and applications) rely on.
 */
class AuthoritiesMappingPropertiesTest {

    @Configuration
    @EnableConfigurationProperties(AuthoritiesMappingProperties.class)
    static class TestConfig {
    }

    private final ApplicationContextRunner contextRunner =
            new ApplicationContextRunner().withUserConfiguration(TestConfig.class);

    @Test
    void givenNoAuthoritiesPropertiesConfigured_whenBinding_thenMappingsListIsEmpty() {
        contextRunner.run(context -> {
            AuthoritiesMappingProperties properties = context.getBean(AuthoritiesMappingProperties.class);
            assertThat(properties.getMappings()).isEmpty();
        });
    }

    @Test
    void givenMultipleMappingsConfigured_whenBinding_thenPathsAndPrefixesAreBoundInOrder() {
        contextRunner
                .withPropertyValues(
                        "trust.security.authorities.mappings[0].path=permissions.roles",
                        "trust.security.authorities.mappings[0].prefix=ROLE_",
                        "trust.security.authorities.mappings[1].path=application.{clientId}.roles",
                        "trust.security.authorities.mappings[1].prefix=ROLE_")
                .run(context -> {
                    AuthoritiesMappingProperties properties = context.getBean(AuthoritiesMappingProperties.class);
                    assertThat(properties.getMappings()).containsExactly(
                            new AuthorityClaimMapping("permissions.roles", "ROLE_", null),
                            new AuthorityClaimMapping("application.{clientId}.roles", "ROLE_", null));
                });
    }
}
