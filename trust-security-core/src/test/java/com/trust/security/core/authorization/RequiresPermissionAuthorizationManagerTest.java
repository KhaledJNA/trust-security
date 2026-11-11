package com.trust.security.core.authorization;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class RequiresPermissionAuthorizationManagerTest {

    @Mock
    private RequiresPermissionResolver permissionResolver;
    @Mock
    private AuthorizationResourceIdResolver resourceIdResolver;
    @Mock
    private PermissionContextProviderResolver contextProviderResolver;
    @Mock
    private PermissionChecker permissionChecker;
    @Mock
    private PermissionContextProvider provider;
    @Mock
    private MethodInvocation invocation;
    @Mock
    private Authentication authentication;

    private RequiresPermissionAuthorizationManager authorizationManager;

    @BeforeEach
    void setUp() {
        authorizationManager = new RequiresPermissionAuthorizationManager(
                permissionResolver, resourceIdResolver, contextProviderResolver, permissionChecker);
    }

    interface Service {
        void doSomething();
    }

    static class ServiceImpl implements Service {
        @Override
        public void doSomething() {
        }
    }

    static class StubProvider implements PermissionContextProvider {
        @Override
        public Map<String, String> resolve(Object resourceId) {
            return Map.of();
        }
    }

    @RequiresPermission(resource = "orders", scope = "read")
    private static class AnnotationHolder {
    }

    private static Method serviceMethod() throws NoSuchMethodException {
        return Service.class.getMethod("doSomething");
    }

    private static RequiresPermission requiresPermission() {
        return AnnotationHolder.class.getAnnotation(RequiresPermission.class);
    }

    @Test
    void givenNullPermissionResolver_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() ->
                new RequiresPermissionAuthorizationManager(null, resourceIdResolver, contextProviderResolver, permissionChecker));
    }

    @Test
    void givenNullResourceIdResolver_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() ->
                new RequiresPermissionAuthorizationManager(permissionResolver, null, contextProviderResolver, permissionChecker));
    }

    @Test
    void givenNullContextProviderResolver_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() ->
                new RequiresPermissionAuthorizationManager(permissionResolver, resourceIdResolver, null, permissionChecker));
    }

    @Test
    void givenNullPermissionChecker_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException().isThrownBy(() ->
                new RequiresPermissionAuthorizationManager(permissionResolver, resourceIdResolver, contextProviderResolver, null));
    }

    @Test
    void givenNullInvocation_whenAuthorizing_thenAccessIsDeniedWithoutAnyCollaboration() {
        AuthorizationResult result = authorizationManager.authorize(() -> authentication, null);

        assertThat(result.isGranted()).isFalse();
        verifyNoInteractions(permissionResolver, resourceIdResolver, contextProviderResolver, permissionChecker);
    }

    @Test
    void givenNoRequiresPermissionAnnotationResolved_whenAuthorizing_thenAccessIsDeniedWithoutEvaluatingAuthentication() throws Exception {
        Method method = serviceMethod();
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new ServiceImpl());
        given(permissionResolver.resolve(method, ServiceImpl.class)).willReturn(null);

        AuthorizationResult result = authorizationManager.authorize(
                () -> {
                    throw new AssertionError("authentication should not be evaluated when no @RequiresPermission is resolved");
                },
                invocation);

        assertThat(result.isGranted()).isFalse();
        verifyNoInteractions(resourceIdResolver, contextProviderResolver, permissionChecker);
    }

    @Test
    void givenNoCurrentAuthentication_whenAuthorizing_thenAccessIsDeniedWithoutResolvingResourceOrPermission() throws Exception {
        Method method = serviceMethod();
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new ServiceImpl());
        given(permissionResolver.resolve(method, ServiceImpl.class)).willReturn(requiresPermission());

        AuthorizationResult result = authorizationManager.authorize(() -> null, invocation);

        assertThat(result.isGranted()).isFalse();
        verifyNoInteractions(resourceIdResolver, contextProviderResolver, permissionChecker);
    }

    @Test
    void givenNoAuthorizationResourceIdParameter_whenAuthorizing_thenPermissionCheckerIsCalledWithEmptyContext() throws Exception {
        Method method = serviceMethod();
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new ServiceImpl());
        given(permissionResolver.resolve(method, ServiceImpl.class)).willReturn(requiresPermission());
        given(resourceIdResolver.resolve(invocation)).willReturn(Optional.empty());
        given(permissionChecker.isAllowed(authentication, "orders", "read", Map.of())).willReturn(true);

        AuthorizationResult result = authorizationManager.authorize(() -> authentication, invocation);

        assertThat(result.isGranted()).isTrue();
        verifyNoInteractions(contextProviderResolver);
    }

    @Test
    void givenResolvedAuthorizationResource_whenAuthorizing_thenContextIsResolvedThroughProviderAndPassedToPermissionChecker() throws Exception {
        Method method = serviceMethod();
        ResolvedAuthorizationResource resource =
                new ResolvedAuthorizationResource("order-42", StubProvider.class);
        Map<String, String> resolvedContext = Map.of("ownerId", "user-1");

        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new ServiceImpl());
        given(permissionResolver.resolve(method, ServiceImpl.class)).willReturn(requiresPermission());
        given(resourceIdResolver.resolve(invocation)).willReturn(Optional.of(resource));
        given(contextProviderResolver.resolve(StubProvider.class)).willReturn(provider);
        given(provider.resolve("order-42")).willReturn(resolvedContext);
        given(permissionChecker.isAllowed(authentication, "orders", "read", resolvedContext)).willReturn(false);

        AuthorizationResult result = authorizationManager.authorize(() -> authentication, invocation);

        assertThat(result.isGranted()).isFalse();
        verify(permissionChecker).isAllowed(authentication, "orders", "read", resolvedContext);
    }

    @Test
    void givenNoTargetOnInvocation_whenAuthorizing_thenMethodDeclaringClassIsUsedToResolvePermission() throws Exception {
        Method method = serviceMethod();
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(null);
        given(permissionResolver.resolve(method, Service.class)).willReturn(null);

        authorizationManager.authorize(() -> authentication, invocation);

        verify(permissionResolver).resolve(method, Service.class);
    }

    /**
     * A misconfigured provider (resolver returns null, e.g. no matching bean)
     * is a developer/configuration error, not an authorization outcome: it
     * must fail loudly with a message naming the expected provider type,
     * rather than surface as an unexplained NPE or silently allow/deny.
     */
    @Test
    void givenContextProviderCannotBeResolved_whenAuthorizing_thenIllegalStateExceptionNamesTheExpectedProviderType() throws Exception {
        Method method = serviceMethod();
        ResolvedAuthorizationResource resource =
                new ResolvedAuthorizationResource("order-42", StubProvider.class);

        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new ServiceImpl());
        given(permissionResolver.resolve(method, ServiceImpl.class)).willReturn(requiresPermission());
        given(resourceIdResolver.resolve(invocation)).willReturn(Optional.of(resource));
        given(contextProviderResolver.resolve(StubProvider.class)).willReturn(null);

        assertThatIllegalStateException()
                .isThrownBy(() -> authorizationManager.authorize(() -> authentication, invocation))
                .withMessageContaining(StubProvider.class.getName());
    }
}
