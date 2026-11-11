package com.trust.security.client.multichain;

import com.trust.security.web.RequestPatterns;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.boot.autoconfigure.condition.ConditionEvaluationReport;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.Condition;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.env.Environment;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

import java.util.Arrays;

/**
 * Validates, at startup, that this starter can coexist with
 * {@code trust-security-resource-server-starter}.
 * <ul>
 *   <li>Sibling starter's auto-configuration excluded by the application: matches.</li>
 *   <li>Resource-server starter absent: matches.</li>
 *   <li>Present, and both starters declare a {@code multi-chain.request-pattern}
 *   that do not overlap: matches.</li>
 *   <li>Present otherwise: fails startup with a
 *   {@link MultiChainConfigurationException}, instead of letting two
 *   {@code SecurityFilterChain}s silently compete for the same requests.</li>
 * </ul>
 * It never returns {@code false}: it either lets the auto-configuration in
 * or stops the application.
 * <p>
 * The sibling starter is detected by class name and its property read via
 * {@link Binder}, so the two starters have no compile-time dependency on
 * each other. The resource-server starter runs the mirror check, so the
 * verdict does not depend on which auto-configuration is evaluated first.
 */
public final class MultiChainCoexistenceCondition implements Condition {

    static final String RESOURCE_SERVER_AUTO_CONFIGURATION_CLASS = "com.trust.security.resourceserver.ResourceServerAutoConfiguration";

    static final String OWN_REQUEST_PATTERN_PROPERTY =
            "trust.security.oauth2-client.multi-chain.request-pattern";
    static final String RESOURCE_SERVER_REQUEST_PATTERN_PROPERTY =
            "trust.security.resource-server.multi-chain.request-pattern";

    private static final String EXCLUDE_PROPERTY = "spring.autoconfigure.exclude";

    @Override
    public boolean matches(ConditionContext context, AnnotatedTypeMetadata metadata) {
        if (!ClassUtils.isPresent(RESOURCE_SERVER_AUTO_CONFIGURATION_CLASS, context.getClassLoader())
                || isExcluded(context, RESOURCE_SERVER_AUTO_CONFIGURATION_CLASS)) {
            return true;
        }

        String ownPattern = requestPattern(context.getEnvironment(), OWN_REQUEST_PATTERN_PROPERTY);
        String resourceServerPattern = requestPattern(context.getEnvironment(), RESOURCE_SERVER_REQUEST_PATTERN_PROPERTY);

        if (ownPattern == null || resourceServerPattern == null) {
            throw MultiChainConfigurationException.notDeclared();
        }
        if (RequestPatterns.overlap(ownPattern, resourceServerPattern)) {
            throw MultiChainConfigurationException.overlapping(ownPattern, resourceServerPattern);
        }
        return true;
    }

    /**
     * An application may keep both starters on the classpath but exclude the
     * sibling's auto-configuration ({@code @SpringBootApplication(exclude = ...)}
     * or {@code spring.autoconfigure.exclude}): its chain is then never
     * created, so there is nothing to coexist with.
     */
    private static boolean isExcluded(ConditionContext context, String autoConfigurationClass) {
        ConfigurableListableBeanFactory beanFactory = context.getBeanFactory();
        if (beanFactory != null
                && ConditionEvaluationReport.get(beanFactory).getExclusions().contains(autoConfigurationClass)) {
            return true;
        }
        String[] excludedByProperty = Binder.get(context.getEnvironment())
                .bind(EXCLUDE_PROPERTY, Bindable.of(String[].class))
                .orElse(new String[0]);
        return Arrays.stream(excludedByProperty).map(String::trim).anyMatch(autoConfigurationClass::equals);
    }

    private static String requestPattern(Environment environment, String property) {
        String pattern = Binder.get(environment)
                .bind(property, Bindable.of(String.class))
                .orElse(null);
        return StringUtils.hasText(pattern) ? pattern : null;
    }
}
