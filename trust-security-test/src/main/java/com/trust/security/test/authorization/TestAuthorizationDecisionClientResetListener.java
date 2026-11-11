package com.trust.security.test.authorization;

import org.springframework.test.context.TestContext;
import org.springframework.test.context.support.AbstractTestExecutionListener;

/**
 * Resets the {@link TestAuthorizationDecisionClient} after every test method,
 * so rules configured by one test never leak into the next one through
 * Spring's cached test context (shared by every test class with the same
 * configuration).
 * <p>
 * Registered automatically through {@code META-INF/spring.factories}; it does
 * nothing when the test has no application context, or no such bean.
 */
public final class TestAuthorizationDecisionClientResetListener extends AbstractTestExecutionListener {

    @Override
    public void afterTestMethod(TestContext testContext) {
        if (testContext.hasApplicationContext()) {
            testContext.getApplicationContext()
                    .getBeanProvider(TestAuthorizationDecisionClient.class)
                    .ifUnique(TestAuthorizationDecisionClient::reset);
        }
    }
}
