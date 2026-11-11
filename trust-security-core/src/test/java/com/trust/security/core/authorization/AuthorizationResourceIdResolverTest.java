package com.trust.security.core.authorization;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class AuthorizationResourceIdResolverTest {

    static class StubProvider implements PermissionContextProvider {
        @Override
        public Map<String, String> resolve(Object resourceId) {
            return Map.of();
        }
    }

    interface Operations {
        void noAnnotation(String id);

        void singleAnnotated(@AuthorizationResourceId(StubProvider.class) String id);

        void oneAnnotatedAmongSeveral(String other, @AuthorizationResourceId(StubProvider.class) String id);

        void twoAnnotated(
                @AuthorizationResourceId(StubProvider.class) String a,
                @AuthorizationResourceId(StubProvider.class) String b);
    }

    interface UnannotatedOperations {
        void load(String id);
    }

    static class AnnotatedImplementation implements UnannotatedOperations {
        @Override
        public void load(@AuthorizationResourceId(StubProvider.class) String id) {
        }
    }

    @Mock
    private MethodInvocation invocation;

    private final AuthorizationResourceIdResolver resolver = new AuthorizationResourceIdResolver();

    private static Method methodOf(String name, Class<?>... paramTypes) throws NoSuchMethodException {
        return Operations.class.getMethod(name, paramTypes);
    }

    @Test
    void givenNoAnnotatedParameter_whenResolving_thenNothingIsResolved() throws Exception {
        given(invocation.getMethod()).willReturn(methodOf("noAnnotation", String.class));

        Optional<ResolvedAuthorizationResource> resolved = resolver.resolve(invocation);

        assertThat(resolved).isEmpty();
    }

    @Test
    void givenSingleAnnotatedParameter_whenResolving_thenResourceIdAndProviderTypeAreResolved() throws Exception {
        given(invocation.getMethod()).willReturn(methodOf("singleAnnotated", String.class));
        given(invocation.getArguments()).willReturn(new Object[]{"order-42"});

        Optional<ResolvedAuthorizationResource> resolved = resolver.resolve(invocation);

        assertThat(resolved).isPresent();
        assertThat(resolved.get().id()).isEqualTo("order-42");
        assertThat(resolved.get().contextProviderType()).isEqualTo(StubProvider.class);
    }

    @Test
    void givenOneAnnotatedParameterAmongSeveral_whenResolving_thenOnlyAnnotatedArgumentIsResolved() throws Exception {
        given(invocation.getMethod()).willReturn(methodOf("oneAnnotatedAmongSeveral", String.class, String.class));
        given(invocation.getArguments()).willReturn(new Object[]{"unrelated", "order-42"});

        Optional<ResolvedAuthorizationResource> resolved = resolver.resolve(invocation);

        assertThat(resolved).isPresent();
        assertThat(resolved.get().id()).isEqualTo("order-42");
    }

    @Test
    void givenTwoAnnotatedParameters_whenResolving_thenIllegalStateExceptionIsThrown() throws Exception {
        given(invocation.getMethod()).willReturn(methodOf("twoAnnotated", String.class, String.class));

        assertThatIllegalStateException()
                .isThrownBy(() -> resolver.resolve(invocation))
                .withMessage("Only one @AuthorizationResourceId is allowed per method");
    }

    @Test
    void givenAnnotatedParameterWithNullArgumentValue_whenResolving_thenIllegalStateExceptionIsThrown() throws Exception {
        given(invocation.getMethod()).willReturn(methodOf("singleAnnotated", String.class));
        given(invocation.getArguments()).willReturn(new Object[]{null});

        assertThatIllegalStateException()
                .isThrownBy(() -> resolver.resolve(invocation))
                .withMessage("@AuthorizationResourceId value must not be null");
    }


    @Test
    void givenAnnotationOnImplementationParameterOnly_whenResolvingInterfaceMethod_thenResourceIdIsResolved() throws Exception {
        given(invocation.getMethod()).willReturn(UnannotatedOperations.class.getMethod("load", String.class));
        given(invocation.getThis()).willReturn(new AnnotatedImplementation());
        given(invocation.getArguments()).willReturn(new Object[]{"order-42"});

        Optional<ResolvedAuthorizationResource> resolved = resolver.resolve(invocation);

        assertThat(resolved).isPresent();
        assertThat(resolved.get().id()).isEqualTo("order-42");
        assertThat(resolved.get().contextProviderType()).isEqualTo(StubProvider.class);
    }
}
