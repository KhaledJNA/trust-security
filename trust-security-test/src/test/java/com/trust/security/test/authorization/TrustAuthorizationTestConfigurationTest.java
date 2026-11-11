package com.trust.security.test.authorization;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the contract an application actually relies on: importing
 * {@link TrustAuthorizationTestConfiguration} supplies exactly the
 * {@link AuthorizationDecisionClient} bean the application's real
 * {@code @RequiresPermission} wiring needs - nothing else, no provider, no
 * network.
 */
class TrustAuthorizationTestConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(TrustAuthorizationTestConfiguration.class));

    @Test
    void whenImported_thenAnAuthorizationDecisionClientBeanIsAvailable() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(AuthorizationDecisionClient.class);
            assertThat(context.getBean(AuthorizationDecisionClient.class))
                    .isInstanceOf(TestAuthorizationDecisionClient.class);
        });
    }

    @Test
    void whenImported_thenTheBeanIsControllableFromTheTest() {
        contextRunner.run(context -> {
            TestAuthorizationDecisionClient client = context.getBean(TestAuthorizationDecisionClient.class);
            client.permit("Document", "modify");

            AuthorizationDecisionClient asPort = context.getBean(AuthorizationDecisionClient.class);

            assertThat(asPort).isSameAs(client);
        });
    }
}
