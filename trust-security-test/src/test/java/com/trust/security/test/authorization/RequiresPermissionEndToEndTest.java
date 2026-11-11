package com.trust.security.test.authorization;

import com.trust.security.core.authorization.AuthorizationRequest;
import com.trust.security.core.authorization.AuthorizationResourceIdResolver;
import com.trust.security.core.authorization.PermissionChecker;
import com.trust.security.core.authorization.PermissionContextProviderResolver;
import com.trust.security.core.authorization.RequiresPermission;
import com.trust.security.core.authorization.RequiresPermissionAuthorizationManager;
import com.trust.security.core.authorization.RequiresPermissionResolver;
import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

import java.lang.reflect.Method;
import java.util.Map;

import static org.mockito.BDDMockito.given;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Demonstrates - and locks in - the whole point of this module: an
 * application's real {@code @RequiresPermission} chain
 * ({@link RequiresPermissionResolver}, {@link RequiresPermissionAuthorizationManager})
 * runs unmodified; only the outermost {@link com.trust.security.core.authorization.AuthorizationDecisionClient}
 * boundary is replaced by {@link TestAuthorizationDecisionClient}.
 * <p>
 * The bridge from {@link PermissionChecker} to {@code AuthorizationDecisionClient}
 * below is intentionally written out in full (rather than imported from a
 * starter): trust-security-test stays independent of any specific starter,
 * and this is exactly the one-line adapter every starter provides in
 * production (see {@code ResourceServerPermissionChecker}).
 */
@ExtendWith(MockitoExtension.class)
class RequiresPermissionEndToEndTest {

    private record BridgePermissionChecker(TestAuthorizationDecisionClient decisionClient) implements PermissionChecker {
        @Override
        public boolean isAllowed(Authentication authentication, String resource, String scope, Map<String, String> context) {
            return decisionClient.isAllowed(new AuthorizationRequest(authentication, resource, scope, context));
        }
    }

    @Mock
    private MethodInvocation invocation;

    private TestAuthorizationDecisionClient decisionClient;
    private RequiresPermissionAuthorizationManager authorizationManager;

    private interface DocumentService {
        @RequiresPermission(resource = "Document", scope = "modify")
        void modifyContract();
    }

    private static class DocumentServiceImpl implements DocumentService {
        @Override
        public void modifyContract() {
        }
    }

    @BeforeEach
    void setUp() throws Exception {
        decisionClient = new TestAuthorizationDecisionClient();

        Method method = DocumentService.class.getMethod("modifyContract");
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new DocumentServiceImpl());

        authorizationManager = new RequiresPermissionAuthorizationManager(
                new RequiresPermissionResolver(),
                new AuthorizationResourceIdResolver(),
                emptyContextProviderResolver(),
                new BridgePermissionChecker(decisionClient));
    }

    private static PermissionContextProviderResolver emptyContextProviderResolver() {
        return providerType -> {
            throw new AssertionError("no @AuthorizationResourceId parameter on this method: must not be called");
        };
    }

    @Test
    void givenTestClientPermits_whenTheRealAopChainAuthorizes_thenAccessIsGranted() {
        decisionClient.permit("Document", "modify");
        Authentication authentication = new TestingAuthenticationToken("user-123", "n/a");

        AuthorizationResult result = authorizationManager.authorize(() -> authentication, invocation);

        assertThat(result.isGranted()).isTrue();
    }

    @Test
    void givenTestClientDenies_whenTheRealAopChainAuthorizes_thenAccessIsDenied() {
        decisionClient.deny("Document", "modify");
        Authentication authentication = new TestingAuthenticationToken("user-123", "n/a");

        AuthorizationResult result = authorizationManager.authorize(() -> authentication, invocation);

        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void givenNoRuleConfigured_whenTheRealAopChainAuthorizes_thenAccessIsDeniedFailClosed() {
        Authentication authentication = new TestingAuthenticationToken("user-123", "n/a");

        AuthorizationResult result = authorizationManager.authorize(() -> authentication, invocation);

        assertThat(result.isGranted()).isFalse();
    }

    @Test
    void whenTheRealAopChainAuthorizes_thenTheDecisionClientObservedTheResourceAndAction() {
        decisionClient.permit("Document", "modify");
        Authentication authentication = new TestingAuthenticationToken("user-123", "n/a");

        authorizationManager.authorize(() -> authentication, invocation);

        assertThat(decisionClient.lastRequest()).isPresent();
        assertThat(decisionClient.lastRequest().get().resource()).isEqualTo("Document");
        assertThat(decisionClient.lastRequest().get().action()).isEqualTo("modify");
        assertThat(decisionClient.lastRequest().get().authentication()).isSameAs(authentication);
    }
}
