package com.trust.security.client.tenant;

import com.trust.security.client.OAuth2ClientSecurityProperties;
import com.trust.security.web.RequestPatterns;
import com.trust.web.problem.ProblemDetailsWriter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Tenant login: resolves a {@code registrationId} from the request host or
 * path, then redirects to Spring's {@code /oauth2/authorization/{registrationId}}.
 * <p>
 * Active only when {@code trust.security.oauth2-client.login.registration-id-resolution}
 * is configured. Every configuration error is detected at startup, never at
 * the first login attempt - see {@link RegistrationIdResolutionConfigurationException}.
 */
@Configuration(proxyBeanMethods = false)
@Conditional(RegistrationIdResolutionConfiguredCondition.class)
public class TenantLoginConfiguration {

    private static final List<String> RESERVED_SPRING_OAUTH2_PATHS = List.of(
            "/oauth2/authorization",
            "/login/oauth2/code",
            "/logout/connect/back-channel");

    /**
     * An application-supplied {@link TrustRegistrationIdResolver} replaces
     * this one, and with it the {@code source}/{@code mappings} validations,
     * which only apply to it. The {@code request-pattern} is validated by
     * {@link #tenantLoginRequestFilter} in every case.
     */
    @Bean
    @ConditionalOnMissingBean(TrustRegistrationIdResolver.class)
    TrustRegistrationIdResolver trustRegistrationIdResolver(
            OAuth2LoginProperties loginProperties,
            ClientRegistrationRepository clientRegistrationRepository) {

        OAuth2LoginProperties.RegistrationIdResolution config = loginProperties.getRegistrationIdResolution();

        validateSourceAndVariableName(config);
        validateMappingsAgainstRepository(config.getMappings(), clientRegistrationRepository);

        return switch (config.getSource()) {
            case HOST -> new HostTrustRegistrationIdResolver(config.getMappings());
            case PATH -> new PathVariableTrustRegistrationIdResolver(
                    config.getRequestPattern(), config.getVariableName(), config.getMappings());
        };
    }

    /** Added to {@code oauth2ClientFilterChain} by {@code OAuth2ClientAutoConfiguration}. */
    @Bean
    TenantLoginRequestFilter tenantLoginRequestFilter(
            OAuth2LoginProperties loginProperties,
            OAuth2ClientSecurityProperties securityProperties,
            TrustRegistrationIdResolver trustRegistrationIdResolver,
            ProblemDetailsWriter problemDetailsWriter) {

        String requestPattern = loginProperties.getRegistrationIdResolution().getRequestPattern();
        validateRequestPatternDoesNotOverlapSpringEndpoints(requestPattern, securityProperties.getLogoutPath());

        return new TenantLoginRequestFilter(
                requestPattern,
                trustRegistrationIdResolver,
                problemDetailsWriter);
    }

    private static void validateRequestPatternDoesNotOverlapSpringEndpoints(String requestPattern, String logoutPath) {
        List<String> reserved = new ArrayList<>(RESERVED_SPRING_OAUTH2_PATHS);
        reserved.add(logoutPath);

        for (String reservedPath : reserved) {
            if (RequestPatterns.overlap(requestPattern, reservedPath)) {
                throw RegistrationIdResolutionConfigurationException.conflictingRequestPattern(
                        requestPattern, reservedPath);
            }
        }
    }

    private static void validateSourceAndVariableName(OAuth2LoginProperties.RegistrationIdResolution config) {
        boolean hasVariableName = config.getVariableName() != null && !config.getVariableName().isBlank();

        if (config.getSource() == OAuth2LoginProperties.Source.PATH) {
            if (!hasVariableName) {
                throw RegistrationIdResolutionConfigurationException.missingVariableName();
            }
            if (!config.getRequestPattern().contains("{" + config.getVariableName() + "}")) {
                throw RegistrationIdResolutionConfigurationException.variableNotInPattern(
                        config.getRequestPattern(), config.getVariableName());
            }
        } else if (hasVariableName) {
            throw RegistrationIdResolutionConfigurationException.unexpectedVariableNameForHostSource();
        }
    }

    private static void validateMappingsAgainstRepository(
            Map<String, String> mappings, ClientRegistrationRepository clientRegistrationRepository) {

        mappings.forEach((mappedValue, registrationId) -> {
            if (clientRegistrationRepository.findByRegistrationId(registrationId) == null) {
                throw RegistrationIdResolutionConfigurationException.unknownRegistrationId(
                        mappedValue, registrationId);
            }
        });
    }
}
