package com.trust.security.web;

import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.core.type.MethodMetadata;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Set;

/**
 * Backs off only when a {@code SecurityFilterChain} bean already exists that
 * is either application-supplied, or one of this <em>same</em> starter's own
 * other mutually-exclusive candidate chains - never when it is the
 * <em>sibling</em> Trust security starter's own chain, expected during a
 * validated cohabitation.
 * <p>
 * Replaces the bare {@code @ConditionalOnMissingBean(SecurityFilterChain.class)}
 * every chain bean in both starters used before cohabitation existed. That
 * by-type check served two purposes at once - "let an application-supplied
 * chain win" and "keep this starter's own 3 (resource-server) or 1
 * (oauth2-client) candidate chains mutually exclusive" - and could not
 * distinguish either from "the sibling starter's chain already exists". A
 * naive allowlist of all 4 known bean names would fix cross-starter
 * cohabitation but silently break the *same-starter* exclusivity (e.g. both
 * {@code jwtResourceServerFilterChain} and {@code opaqueTokenResourceServerFilterChain}
 * created together) - this condition keeps both properties: it tolerates
 * only bean names belonging to the *other* starter, identified from the
 * candidate method's own name via {@link MethodMetadata}.
 * <p>
 * Lives here, in the module both security starters already depend on for
 * {@link AcrStepUpAccessDeniedHandler}, rather than being duplicated in each
 * starter's own {@code multichain} package: the well-known bean-name
 * allowlist is security-relevant and must never drift between two copies.
 * This introduces no new coupling between the two starters themselves - they
 * still never depend on each other directly.
 */
public final class NoForeignSecurityFilterChainCondition implements Condition {

    private static final Set<String> RESOURCE_SERVER_BEAN_NAMES = Set.of(
            "jwtResourceServerFilterChain",
            "opaqueTokenResourceServerFilterChain",
            "multiIssuerResourceServerFilterChain");

    private static final String OAUTH2_CLIENT_BEAN_NAME = "oauth2ClientFilterChain";

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        ConfigurableListableBeanFactory beanFactory = context.getBeanFactory();
        if (beanFactory == null) {
            return true;
        }

        boolean thisIsResourceServerBean = metadata instanceof MethodMetadata methodMetadata
                && RESOURCE_SERVER_BEAN_NAMES.contains(methodMetadata.getMethodName());

        for (String existingBeanName : beanFactory.getBeanNamesForType(SecurityFilterChain.class, false, false)) {
            boolean isSiblingStarterBean = thisIsResourceServerBean
                    ? OAUTH2_CLIENT_BEAN_NAME.equals(existingBeanName)
                    : RESOURCE_SERVER_BEAN_NAMES.contains(existingBeanName);
            if (!isSiblingStarterBean) {
                return false;
            }
        }
        return true;
    }
}
