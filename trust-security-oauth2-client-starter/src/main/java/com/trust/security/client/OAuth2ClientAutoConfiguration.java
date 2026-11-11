package com.trust.security.client;

import com.trust.security.client.authorities.AuthoritiesMappingProperties;
import com.trust.security.client.authorities.ClaimGrantedAuthoritiesMapper;
import com.trust.security.client.multichain.MultiChainCoexistenceCondition;
import com.trust.security.client.multichain.MultiChainProperties;
import com.trust.security.client.stepup.AcrOAuth2AuthorizationRequestResolver;
import com.trust.security.client.stepup.AcrStepUpAuthenticationSuccessHandler;
import com.trust.security.client.stepup.AcrStepUpController;
import com.trust.security.client.tenant.OAuth2LoginProperties;
import com.trust.security.client.tenant.TenantLoginConfiguration;
import com.trust.security.client.tenant.TenantLoginRequestFilter;
import com.trust.security.core.acr.AcrAuthorization;
import com.trust.security.core.acr.RequiresAcrAuthorizationManager;
import com.trust.security.core.acr.RequiresAcrPointcut;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import com.trust.security.core.user.CurrentAuthoritiesProvider;
import com.trust.security.core.user.CurrentUserProvider;
import com.trust.security.core.user.SecurityContextCurrentAuthoritiesProvider;
import com.trust.security.core.user.SecurityContextCurrentUserProvider;
import com.trust.security.web.AcrStepUpAccessDeniedHandler;
import com.trust.security.web.NoForeignSecurityFilterChainCondition;
import com.trust.security.web.async.SecurityContextTaskDecorator;
import com.trust.security.web.audit.AuthenticatedSubjectMdcFilter;
import com.trust.security.web.problem.ProblemDetailsAccessDeniedHandler;
import com.trust.web.problem.ProblemDetailsWriter;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.util.StringUtils;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tools.jackson.databind.ObjectMapper;

import java.util.List;
import java.util.stream.Stream;

/**
 * Auto-configuration of the OAuth2 client starter (BFF pattern).
 * <p>
 * STATEFUL, unlike a resource server: the token lives in the server-side
 * session and the browser only gets a cookie, hence CSRF and CORS here.
 * <p>
 * Every bean is conditional: an application can declare its own instead.
 * <p>
 * Running next to {@code trust-security-resource-server-starter} is only
 * possible in "multiple SecurityFilterChain" mode, declared on both sides
 * with two disjoint {@code multi-chain.request-pattern}; otherwise the
 * startup fails (see {@link MultiChainCoexistenceCondition}).
 * <p>
 * Packages:
 * <ul>
 *   <li>{@code authorities}: claims to authorities mapping;</li>
 *   <li>{@code stepup}: ACR step-up authentication;</li>
 *   <li>{@code tenant}: choice of the {@code registrationId} by host or path;</li>
 *   <li>{@code multichain}: running next to the resource-server starter.</li>
 * </ul>
 */
@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties({
        OAuth2ClientSecurityProperties.class,
        SecurityHeadersProperties.class,
        AuthoritiesMappingProperties.class,
        OAuth2LoginProperties.class,
        MultiChainProperties.class})
@Conditional(MultiChainCoexistenceCondition.class)
@Import(TenantLoginConfiguration.class)
public class OAuth2ClientAutoConfiguration {

    private static final String BACK_CHANNEL_LOGOUT_PATH = "/logout/connect/back-channel/**";
    private static final String ACTUATOR_HEALTH_PATH = "/actuator/health";

    // ---------------------------------------------------------------- filter chain

    /**
     * Scoped with {@code securityMatcher} only when
     * {@code trust.security.oauth2-client.multi-chain.request-pattern} is set;
     * otherwise applies to every request. Backs off when the application
     * defines its own {@code SecurityFilterChain}, but not for the
     * resource-server starter's chain - see {@link NoForeignSecurityFilterChainCondition}.
     */
    @Bean
    @Conditional(NoForeignSecurityFilterChainCondition.class)
    public SecurityFilterChain oauth2ClientFilterChain(
            HttpSecurity http,
            SecurityHeadersProperties securityHeadersProperties,
            OAuth2ClientSecurityProperties properties,
            OAuth2LoginProperties loginProperties,
            MultiChainProperties multiChainProperties,
            GrantedAuthoritiesMapper grantedAuthoritiesMapper,
            ClientRegistrationRepository clientRegistrationRepository,
            CorsConfigurationSource corsConfigurationSource,
            OAuth2AuthorizationRequestResolver authorizationRequestResolver,
            ObjectProvider<TenantLoginRequestFilter> tenantLoginRequestFilter,
            RequestCache requestCache,
            @Qualifier("oauth2ClientAuthenticationSuccessHandler")
            AuthenticationSuccessHandler authenticationSuccessHandler,
            @Qualifier("oauth2ClientAcrStepUpAccessDeniedHandler")
            AccessDeniedHandler acrStepUpAccessDeniedHandler) throws Exception {

        if (StringUtils.hasText(multiChainProperties.getRequestPattern())) {
            http.securityMatcher(multiChainProperties.getRequestPattern());
        }

        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
        csrfHandler.setCsrfRequestAttributeName(null);

        String[] publicPaths = Stream.concat(properties.getPublicPaths().stream(), Stream.of(ACTUATOR_HEALTH_PATH))
                .toArray(String[]::new);

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .requestCache(cache -> cache.requestCache(requestCache))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                        .csrfTokenRequestHandler(csrfHandler)
                        .ignoringRequestMatchers(BACK_CHANNEL_LOGOUT_PATH))
                .authorizeHttpRequests(requests -> {
                    requests
                            .requestMatchers(BACK_CHANNEL_LOGOUT_PATH).permitAll()
                            .requestMatchers(publicPaths).permitAll();
                    if (loginProperties.getRegistrationIdResolution() != null) {
                        requests.requestMatchers(loginProperties.getRegistrationIdResolution().getRequestPattern())
                                .permitAll();
                    }
                    requests.anyRequest().authenticated();
                })
                .oauth2Login(login -> login
                        .successHandler(authenticationSuccessHandler)
                        .authorizationEndpoint(authorization ->
                                authorization.authorizationRequestResolver(authorizationRequestResolver))
                        .userInfoEndpoint(userInfo -> userInfo.userAuthoritiesMapper(grantedAuthoritiesMapper)))
                .oidcLogout(oidc -> oidc.backChannel(backChannel -> {
                }))
                .exceptionHandling(exceptions -> exceptions.accessDeniedHandler(acrStepUpAccessDeniedHandler))
                .logout(logout -> logout
                        .logoutUrl(properties.getLogoutPath())
                        .logoutSuccessHandler(oidcLogoutSuccessHandler(clientRegistrationRepository, properties))
                        .invalidateHttpSession(true)
                        .addLogoutHandler(new SessionCookieClearingLogoutHandler()))
                .headers(headers -> configureContentSecurityPolicy(securityHeadersProperties, headers))
                .addFilterAfter(new AuthenticatedSubjectMdcFilter(), SecurityContextHolderFilter.class);

        tenantLoginRequestFilter.ifAvailable(filter ->
                http.addFilterBefore(filter, OAuth2AuthorizationRequestRedirectFilter.class));

        return http.build();
    }

    private static void configureContentSecurityPolicy(
            SecurityHeadersProperties properties, HeadersConfigurer<HttpSecurity> headers) {

        SecurityHeadersProperties.ContentSecurityPolicy csp = properties.getContentSecurityPolicy();
        if (csp.isEnabled()) {
            headers.contentSecurityPolicy(configurer -> configurer.policyDirectives(csp.getPolicy()));
        }
    }

    private static LogoutSuccessHandler oidcLogoutSuccessHandler(
            ClientRegistrationRepository repository, OAuth2ClientSecurityProperties properties) {

        OidcClientInitiatedLogoutSuccessHandler handler = new OidcClientInitiatedLogoutSuccessHandler(repository);
        handler.setPostLogoutRedirectUri(properties.getPostLogoutRedirectUri());
        return handler;
    }

    /**
     * Never saves fetch/XHR requests (e.g. an SPA's {@code GET /api/me}
     * probe) as the post-login target - see {@link NavigationRequestMatcher}.
     * An application-supplied {@code RequestCache} (e.g. {@code NullRequestCache})
     * replaces it.
     */
    @Bean
    @ConditionalOnMissingBean(RequestCache.class)
    public RequestCache oauth2ClientRequestCache() {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setRequestMatcher(NavigationRequestMatcher.INSTANCE);
        return requestCache;
    }

    @Bean
    @ConditionalOnMissingBean
    public CorsConfigurationSource corsConfigurationSource(OAuth2ClientSecurityProperties properties) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(properties.getAllowedOrigins());
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"));
        config.setAllowedHeaders(List.of("*"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    // ---------------------------------------------------------------- login

    @Bean
    @ConditionalOnMissingBean
    public ClaimAuthoritiesMapper claimAuthoritiesMapper(AuthoritiesMappingProperties properties) {
        return new ClaimAuthoritiesMapper(properties.getMappings());
    }

    @Bean
    @ConditionalOnMissingBean
    public GrantedAuthoritiesMapper claimGrantedAuthoritiesMapper(ClaimAuthoritiesMapper claimAuthoritiesMapper) {
        return new ClaimGrantedAuthoritiesMapper(claimAuthoritiesMapper);
    }

    @Bean
    @ConditionalOnMissingBean(OAuth2AuthorizationRequestResolver.class)
    public OAuth2AuthorizationRequestResolver authorizationRequestResolver(
            ClientRegistrationRepository clientRegistrationRepository) {

        return new AcrOAuth2AuthorizationRequestResolver(clientRegistrationRepository);
    }

    /**
     * {@code post-login-redirect-uri} is only the fallback: a saved request
     * (a protected URL denied before login) is still replayed first.
     */
    @Bean
    @ConditionalOnMissingBean(name = "oauth2ClientAuthenticationSuccessHandler")
    public AuthenticationSuccessHandler oauth2ClientAuthenticationSuccessHandler(
            OAuth2ClientSecurityProperties properties) {

        SavedRequestAwareAuthenticationSuccessHandler delegate = new SavedRequestAwareAuthenticationSuccessHandler();
        if (StringUtils.hasText(properties.getPostLoginRedirectUri())) {
            delegate.setDefaultTargetUrl(properties.getPostLoginRedirectUri());
        }
        return new AcrStepUpAuthenticationSuccessHandler(delegate);
    }

    @Bean
    @ConditionalOnMissingBean
    public OAuth2AuthorizationExceptionHandler oauth2AuthorizationExceptionHandler() {
        return new OAuth2AuthorizationExceptionHandler();
    }

    // ---------------------------------------------------------------- ACR step-up

    @Bean
    @ConditionalOnMissingBean
    public AcrAuthorization acrAuthorization() {
        return new AcrAuthorization();
    }

    /**
     * Bean names prefixed with {@code oauth2Client} here and below: the
     * resource-server starter defines equivalent beans, and both starters can
     * run in the same application.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnMissingBean(name = "oauth2ClientRequiresAcrAuthorizationInterceptor")
    public AuthorizationManagerBeforeMethodInterceptor oauth2ClientRequiresAcrAuthorizationInterceptor(
            AcrAuthorization acrAuthorization) {

        return new AuthorizationManagerBeforeMethodInterceptor(
                new RequiresAcrPointcut(),
                new RequiresAcrAuthorizationManager(acrAuthorization));
    }

    @Bean
    @ConditionalOnMissingBean
    public AcrStepUpController acrStepUpController() {
        return new AcrStepUpController();
    }

    /**
     * Insufficient ACR: 401 + {@code WWW-Authenticate} (same handler class as
     * the resource-server starter). Any other access denial: 403 Problem Details.
     */
    @Bean
    @ConditionalOnMissingBean(name = "oauth2ClientAcrStepUpAccessDeniedHandler")
    public AccessDeniedHandler oauth2ClientAcrStepUpAccessDeniedHandler(
            @Qualifier("oauth2ClientAccessDeniedHandler") AccessDeniedHandler oauth2ClientAccessDeniedHandler,
            ProblemDetailsWriter problemDetailsWriter) {

        return new AcrStepUpAccessDeniedHandler(oauth2ClientAccessDeniedHandler, problemDetailsWriter);
    }

    @Bean
    @ConditionalOnMissingBean(name = "oauth2ClientAccessDeniedHandler")
    public AccessDeniedHandler oauth2ClientAccessDeniedHandler(ProblemDetailsWriter problemDetailsWriter) {
        AccessDeniedHandler forbidden = (request, response, exception) ->
                response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        return new ProblemDetailsAccessDeniedHandler(forbidden, problemDetailsWriter);
    }

    // ---------------------------------------------------------------- shared infrastructure

    @Bean
    @ConditionalOnMissingBean
    public ProblemDetailsWriter securityProblemDetailsWriter(ObjectMapper objectMapper) {
        return new ProblemDetailsWriter(objectMapper);
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityContextTaskDecorator securityContextTaskDecorator() {
        return new SecurityContextTaskDecorator();
    }

    @Bean
    @ConditionalOnMissingBean(CurrentUserProvider.class)
    public CurrentUserProvider currentUserProvider() {
        return new SecurityContextCurrentUserProvider();
    }

    @Bean
    @ConditionalOnMissingBean(CurrentAuthoritiesProvider.class)
    public CurrentAuthoritiesProvider currentAuthoritiesProvider() {
        return new SecurityContextCurrentAuthoritiesProvider();
    }
}
