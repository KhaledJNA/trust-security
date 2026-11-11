package com.trust.security.resourceserver.authorization;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.trust.security.core.authorization.AuthorizationDecisionClient;
import com.trust.security.core.authorization.AuthorizationRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Behavioral tests for {@link ResourceServerPermissionChecker}.
 * <p>
 * Deliberately verifies there is no Keycloak/UMA-specific behavior, and no
 * assumption whatsoever about the {@link Authentication} implementation
 * type: this class only builds an {@link AuthorizationRequest} - preserving
 * the authentication reference, mapping {@code scope} to {@code action} -
 * and delegates to whatever {@link AuthorizationDecisionClient} is configured.
 * <p>
 * Also verifies the deny-mode behavior when no {@link AuthorizationDecisionClient}
 * is available: no network call, no exception, a refusal identical in shape
 * to an actual PDP saying no, and a one-time WARN log at construction.
 */
@ExtendWith(MockitoExtension.class)
class ResourceServerPermissionCheckerTest {

    @Mock
    private AuthorizationDecisionClient authorizationDecisionClient;

    private ListAppender<ILoggingEvent> logAppender;

    @BeforeEach
    void setUp() {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ResourceServerPermissionChecker.class);
        logAppender = new ListAppender<>();
        logAppender.start();
        logger.addAppender(logAppender);
    }

    @AfterEach
    void tearDown() {
        ch.qos.logback.classic.Logger logger =
                (ch.qos.logback.classic.Logger) org.slf4j.LoggerFactory.getLogger(ResourceServerPermissionChecker.class);
        logger.detachAppender(logAppender);
    }

    private static ObjectProvider<AuthorizationDecisionClient> providing(AuthorizationDecisionClient client) {
        return new ObjectProvider<>() {
            @Override
            public AuthorizationDecisionClient getObject() {
                return client;
            }

            @Override
            public AuthorizationDecisionClient getObject(Object... args) {
                return client;
            }
        };
    }

    private static ObjectProvider<AuthorizationDecisionClient> providingNothing() {
        return providing(null);
    }

    @Test
    void givenArguments_whenCheckingPermission_thenAnEquivalentAuthorizationRequestIsBuiltAndTrueIsPropagated() {
        ResourceServerPermissionChecker checker =
                new ResourceServerPermissionChecker(providing(authorizationDecisionClient));

        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of());
        Map<String, String> context = Map.of("tenant", "tenant-a");
        AuthorizationRequest expectedRequest =
                new AuthorizationRequest(authentication, "Document", "modify", context);
        given(authorizationDecisionClient.isAllowed(expectedRequest)).willReturn(true);

        boolean allowed = checker.isAllowed(authentication, "Document", "modify", context);

        assertThat(allowed).isTrue();
        verify(authorizationDecisionClient).isAllowed(expectedRequest);
    }

    @Test
    void givenAuthorizationDecisionClientDenies_whenCheckingPermission_thenFalseIsPropagated() {
        ResourceServerPermissionChecker checker =
                new ResourceServerPermissionChecker(providing(authorizationDecisionClient));

        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of());
        AuthorizationRequest expectedRequest =
                new AuthorizationRequest(authentication, "Document", "modify", Map.of());
        given(authorizationDecisionClient.isAllowed(expectedRequest)).willReturn(false);

        boolean allowed = checker.isAllowed(authentication, "Document", "modify", Map.of());

        assertThat(allowed).isFalse();
    }

    @Test
    void givenNoAuthorizationDecisionClientAvailable_whenConstructing_thenNoExceptionAndAWarnIsLoggedOnce() {
        new ResourceServerPermissionChecker(providingNothing());

        assertThat(logAppender.list)
                .hasSize(1)
                .first()
                .satisfies(event -> {
                    assertThat(event.getLevel()).isEqualTo(Level.WARN);
                    assertThat(event.getFormattedMessage())
                            .contains("deny mode")
                            .contains("AuthorizationDecisionClient");
                });
    }

    @Test
    void givenNoAuthorizationDecisionClientAvailable_whenCheckingPermission_thenRefusedWithoutNetworkCallOrException() {
        ResourceServerPermissionChecker checker =
                new ResourceServerPermissionChecker(providingNothing());

        Authentication authentication =
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of());

        boolean allowed = checker.isAllowed(authentication, "Document", "modify", Map.of());

        assertThat(allowed).isFalse();
        verifyNoInteractions(authorizationDecisionClient);
    }
}
