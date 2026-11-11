package com.trust.security.test.authorization;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import com.trust.security.core.authorization.AuthorizationRequest;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Two ordered tests sharing one cached Spring context: the rule configured by
 * the first one must not survive into the second.
 */
@SpringJUnitConfig(TrustAuthorizationTestConfiguration.class)
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TestAuthorizationDecisionClientResetListenerTest {

    private static final AuthorizationRequest MODIFY_CONTRACT = new AuthorizationRequest(
            new TestingAuthenticationToken("user", "n/a"), "Document", "modify", Map.of());

    @Autowired
    private TestAuthorizationDecisionClient decisionClient;

    @Test
    @Order(1)
    void firstTestPermits() {
        decisionClient.permit("Document", "modify");

        assertThat(decisionClient.isAllowed(MODIFY_CONTRACT)).isTrue();
    }

    @Test
    @Order(2)
    void secondTestStartsFromAFreshFailClosedClient() {
        assertThat(decisionClient.lastRequest()).isEmpty();
        assertThat(decisionClient.isAllowed(MODIFY_CONTRACT)).isFalse();
    }

    @Test
    void whenTheApplicationDeclaresItsOwnClient_thenTheTestClientWins() {
        new ApplicationContextRunner()
                .withUserConfiguration(ApplicationClientConfiguration.class, TrustAuthorizationTestConfiguration.class)
                .run(context -> assertThat(context.getBean(AuthorizationDecisionClient.class))
                        .isInstanceOf(TestAuthorizationDecisionClient.class));
    }

    @Configuration(proxyBeanMethods = false)
    static class ApplicationClientConfiguration {

        @Bean
        AuthorizationDecisionClient authorizationDecisionClient() {
            return request -> true;
        }
    }
}
