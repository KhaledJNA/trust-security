package com.trust.security.client.stepup;

import jakarta.servlet.http.HttpServletRequest;
import org.jspecify.annotations.Nullable;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.StringUtils;

import java.util.Objects;

public final class AcrOAuth2AuthorizationRequestResolver
        implements OAuth2AuthorizationRequestResolver {

    private static final String ACR_VALUES = "acr_values";

    private final OAuth2AuthorizationRequestResolver delegate;

    public AcrOAuth2AuthorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        Objects.requireNonNull(
                clientRegistrationRepository,
                "clientRegistrationRepository must not be null"
        );

        this.delegate = new DefaultOAuth2AuthorizationRequestResolver(
                clientRegistrationRepository,
                OAuth2AuthorizationRequestRedirectFilter
                        .DEFAULT_AUTHORIZATION_REQUEST_BASE_URI
        );
    }

    @Override
    public @Nullable OAuth2AuthorizationRequest resolve(
            HttpServletRequest request) {

        return customize(
                request,
                delegate.resolve(request)
        );
    }

    @Override
    public @Nullable OAuth2AuthorizationRequest resolve(
            HttpServletRequest request,
            String clientRegistrationId) {

        return customize(
                request,
                delegate.resolve(request, clientRegistrationId)
        );
    }

    private @Nullable OAuth2AuthorizationRequest customize(
            HttpServletRequest request,
            @Nullable OAuth2AuthorizationRequest authorizationRequest) {

        if (authorizationRequest == null) {
            return null;
        }

        String acrValues = request.getParameter(ACR_VALUES);

        if (!StringUtils.hasText(acrValues)) {
            return authorizationRequest;
        }

        return OAuth2AuthorizationRequest
                .from(authorizationRequest)
                .additionalParameters(parameters ->
                        parameters.put(ACR_VALUES, acrValues))
                .build();
    }
}