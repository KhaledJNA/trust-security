package com.trust.security.core.acr;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

import java.lang.reflect.Method;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class RequiresAcrAuthorizationManagerTest {

    @Mock
    private AcrAuthorization acrAuthorization;

    @Mock
    private Authentication authentication;

    @Mock
    private MethodInvocation invocation;

    private RequiresAcrAuthorizationManager authorizationManager;

    @BeforeEach
    void setUp() {
        authorizationManager = new RequiresAcrAuthorizationManager(acrAuthorization);
    }

    static class NotAnnotated {
        public void open() {
        }
    }

    static class Annotated {
        @RequiresAcr("urn:acr:mfa")
        public void secured() {
        }
    }

    private static Method methodOf(Class<?> type, String name) throws NoSuchMethodException {
        return type.getMethod(name);
    }

    @Test
    void givenMethodWithoutRequiresAcr_whenAuthorizing_thenAccessIsGrantedWithoutEvaluatingAuthenticationOrAcrCheck() throws Exception {
        Method method = methodOf(NotAnnotated.class, "open");
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new NotAnnotated());

        AuthorizationResult result = authorizationManager.authorize(
                () -> {
                    throw new AssertionError("authentication should not be evaluated when no @RequiresAcr is present");
                },
                invocation);

        assertThat(result.isGranted()).isTrue();
        assertThat(((AcrAuthorizationResult) result).requiredAcr()).isNull();
        verifyNoInteractions(acrAuthorization);
    }

    @Test
    void givenMethodWithRequiresAcrAndMatchingAcr_whenAuthorizing_thenAccessIsGranted() throws Exception {
        Method method = methodOf(Annotated.class, "secured");
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new Annotated());
        given(acrAuthorization.hasAcr(authentication, "urn:acr:mfa")).willReturn(true);

        AuthorizationResult result = authorizationManager.authorize(() -> authentication, invocation);

        assertThat(result.isGranted()).isTrue();
        assertThat(((AcrAuthorizationResult) result).requiredAcr()).isEqualTo("urn:acr:mfa");
    }

    @Test
    void givenMethodWithRequiresAcrAndMismatchingAcr_whenAuthorizing_thenAccessIsDenied() throws Exception {
        Method method = methodOf(Annotated.class, "secured");
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(new Annotated());
        given(acrAuthorization.hasAcr(authentication, "urn:acr:mfa")).willReturn(false);

        AuthorizationResult result = authorizationManager.authorize(() -> authentication, invocation);

        assertThat(result.isGranted()).isFalse();
        assertThat(((AcrAuthorizationResult) result).requiredAcr()).isEqualTo("urn:acr:mfa");
    }

    /**
     * Harmonized with {@code RequiresPermissionAuthorizationManager}: when the
     * proxied invocation has no target (e.g. a static method), the method's
     * declaring class is used to resolve {@code @RequiresAcr} instead of
     * dereferencing a null {@code getThis()}.
     */
    @Test
    void givenNoTargetOnInvocation_whenAuthorizing_thenMethodDeclaringClassIsUsedToResolveAcrWithoutNullPointerException() throws Exception {
        Method method = methodOf(Annotated.class, "secured");
        given(invocation.getMethod()).willReturn(method);
        given(invocation.getThis()).willReturn(null);
        given(acrAuthorization.hasAcr(authentication, "urn:acr:mfa")).willReturn(true);

        AuthorizationResult result = authorizationManager.authorize(() -> authentication, invocation);

        assertThat(result.isGranted()).isTrue();
        assertThat(((AcrAuthorizationResult) result).requiredAcr()).isEqualTo("urn:acr:mfa");
    }

    @Test
    void givenNullAcrAuthorization_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new RequiresAcrAuthorizationManager(null))
                .withMessage("acrAuthorization must not be null");
    }
}
