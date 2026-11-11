package com.trust.security.core.authorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.context.ApplicationContext;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
class SpringPermissionContextProviderResolverTest {

    @Mock
    private ApplicationContext applicationContext;

    static class StubProvider implements PermissionContextProvider {
        @Override
        public Map<String, String> resolve(Object resourceId) {
            return Map.of();
        }
    }

    @Test
    void givenNullApplicationContext_whenConstructing_thenNullPointerExceptionIsThrown() {
        assertThatNullPointerException()
                .isThrownBy(() -> new SpringPermissionContextProviderResolver(null));
    }

    @Test
    void givenBeanRegisteredForProviderType_whenResolving_thenThatBeanIsReturned() {
        StubProvider bean = new StubProvider();
        given(applicationContext.getBean(StubProvider.class)).willReturn(bean);
        SpringPermissionContextProviderResolver resolver =
                new SpringPermissionContextProviderResolver(applicationContext);

        PermissionContextProvider resolved = resolver.resolve(StubProvider.class);

        assertThat(resolved).isSameAs(bean);
    }

    @Test
    void givenNoBeanRegisteredForProviderType_whenResolving_thenExceptionFromApplicationContextIsPropagated() {
        given(applicationContext.getBean(StubProvider.class))
                .willThrow(new NoSuchBeanDefinitionException(StubProvider.class));
        SpringPermissionContextProviderResolver resolver =
                new SpringPermissionContextProviderResolver(applicationContext);

        assertThatExceptionOfType(NoSuchBeanDefinitionException.class)
                .isThrownBy(() -> resolver.resolve(StubProvider.class));
    }
}
