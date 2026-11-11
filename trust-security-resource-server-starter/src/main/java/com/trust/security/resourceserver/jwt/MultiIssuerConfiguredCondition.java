package com.trust.security.resourceserver.jwt;

import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;

import java.util.List;

/**
 * Activates multi-issuer JWT mode: {@code true} only when
 * {@code trust.security.resource-server.issuers} is bound to a non-empty
 * list.
 * <p>
 * A dedicated {@link Condition} rather than {@code @ConditionalOnProperty}:
 * that annotation checks a single property's presence/value, not whether a
 * list-valued property has at least one element bound.
 */
public final class MultiIssuerConfiguredCondition implements Condition {

    static final String ISSUERS_PROPERTY = "trust.security.resource-server.issuers";

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        List<IssuerProperties> issuers = Binder.get(context.getEnvironment())
                .bind(ISSUERS_PROPERTY, Bindable.listOf(IssuerProperties.class))
                .orElse(List.of());
        return !issuers.isEmpty();
    }
}
