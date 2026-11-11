package com.trust.security.client.tenant;

import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

/**
 * Activates tenant login-request resolution: {@code true} only when
 * {@code trust.security.oauth2-client.login.registration-id-resolution} is
 * bound to a non-null value.
 * <p>
 * A dedicated {@link Condition} rather than {@code @ConditionalOnProperty}:
 * there is deliberately no {@code enabled} property - the presence of the
 * section itself is the activation signal - and binding the whole nested
 * object (rather than checking one leaf property) is what "the section is
 * configured" actually means here.
 */
final class RegistrationIdResolutionConfiguredCondition implements Condition {

    static final String PROPERTY_PREFIX =
            "trust.security.oauth2-client.login.registration-id-resolution";

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        return Binder.get(context.getEnvironment())
                .bind(PROPERTY_PREFIX, Bindable.of(OAuth2LoginProperties.RegistrationIdResolution.class))
                .isBound();
    }
}
