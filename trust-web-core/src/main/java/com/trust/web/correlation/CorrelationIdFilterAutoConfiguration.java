package com.trust.web.correlation;

import org.jspecify.annotations.NullMarked;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.core.Ordered;

/**
 * Registers {@link CorrelationIdFilter}, shared by every Trust starter that
 * needs it - resource server, OAuth2 client, and REST client (which reads
 * the MDC key this filter populates but has no incoming request of its own
 * to register a servlet filter from).
 *
 * <p>{@code trust-web-core} does not activate this class itself - it ships
 * no {@code AutoConfiguration.imports} file, so declaring it as a dependency
 * changes nothing on its own. Each starter that needs the filter lists this
 * class in its own {@code AutoConfiguration.imports}; Spring Boot merges
 * duplicate entries from multiple jars into a single auto-configuration
 * candidate, so an application combining two or more of those starters still
 * gets exactly one {@link CorrelationIdFilter} registration, not one per
 * starter.
 */
@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class CorrelationIdFilterAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(name = "correlationIdFilterRegistration")
    @NullMarked
    public FilterRegistrationBean<CorrelationIdFilter> correlationIdFilterRegistration() {

        FilterRegistrationBean<CorrelationIdFilter> registration =
                new FilterRegistrationBean<>();

        registration.setFilter(new CorrelationIdFilter());
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE);

        return registration;
    }
}
