package com.trust.security.test.authorization;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Import this into a test (e.g. {@code @Import(TrustAuthorizationTestConfiguration.class)}
 * next to {@code @SpringBootTest}) to supply the missing
 * {@link AuthorizationDecisionClient} bean that the application would
 * otherwise need a real provider adapter (Keycloak UMA, OPA, ...) for.
 * <p>
 * With this imported, the application's real {@code @RequiresPermission}
 * wiring - {@code RequiresPermissionAuthorizationManager}, its resolvers, and
 * whichever {@code PermissionChecker} the application's starter provides -
 * runs exactly as in production. Only the final PDP call is replaced by a
 * {@link TestAuthorizationDecisionClient} the test controls directly.
 * <p>
 * The bean is named {@code testAuthorizationDecisionClient} and is
 * {@link Primary}: it wins even when the application declares
 * its own {@link AuthorizationDecisionClient} bean (a provider auto-configuration
 * such as the Keycloak one backs off by itself). Its rules are reset after
 * every test method by {@link TestAuthorizationDecisionClientResetListener}.
 */
@TestConfiguration
public class TrustAuthorizationTestConfiguration {

    @Bean
    @Primary
    public TestAuthorizationDecisionClient testAuthorizationDecisionClient() {
        return new TestAuthorizationDecisionClient();
    }
}
