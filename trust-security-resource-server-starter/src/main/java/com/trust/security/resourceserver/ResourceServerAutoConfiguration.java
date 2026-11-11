package com.trust.security.resourceserver;

import com.trust.security.resourceserver.authorities.CompositeJwtGrantedAuthoritiesConverter;
import com.trust.security.resourceserver.authorities.JwtClaimAuthoritiesConverter;
import com.trust.security.resourceserver.authorities.TrustOpaqueTokenIntrospector;
import com.trust.security.resourceserver.authorization.ResourceServerPermissionChecker;
import com.trust.security.resourceserver.jwt.JwtDecoderFactory;
import com.trust.security.resourceserver.jwt.MultiIssuerConfiguredCondition;
import com.trust.security.resourceserver.jwt.TrustIssuerAuthenticationManagerResolver;
import com.trust.security.resourceserver.multichain.MultiChainCoexistenceCondition;
import com.trust.security.resourceserver.multichain.MultiChainProperties;
import com.trust.security.web.NoForeignSecurityFilterChainCondition;
import com.trust.security.resourceserver.tokenformat.TokenFormatGuard;
import com.trust.security.resourceserver.tokenformat.AmbiguousTokenFormatException;
import com.trust.security.resourceserver.tokenformat.ConflictingResourceServerModeException;
import com.trust.security.resourceserver.tokenformat.MissingTokenFormatException;
import com.trust.security.core.acr.AcrAuthorization;
import com.trust.security.core.acr.RequiresAcrAuthorizationManager;
import com.trust.security.core.acr.RequiresAcrPointcut;
import com.trust.security.core.authorization.*;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import com.trust.security.core.user.CurrentAuthoritiesProvider;
import com.trust.security.core.user.CurrentUserProvider;
import com.trust.security.core.user.SecurityContextCurrentAuthoritiesProvider;
import com.trust.security.core.user.SecurityContextCurrentUserProvider;
import com.trust.security.web.AcrStepUpAccessDeniedHandler;
import com.trust.security.web.async.SecurityContextTaskDecorator;
import com.trust.security.web.audit.AuthenticatedSubjectMdcFilter;
import com.trust.security.web.problem.ProblemDetailsAccessDeniedHandler;
import com.trust.security.web.problem.ProblemDetailsAuthenticationEntryPoint;
import com.trust.web.problem.ProblemDetailsWriter;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Role;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.oauth2.server.resource.web.access.BearerTokenAccessDeniedHandler;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import tools.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Collection;
import java.util.stream.Stream;

/**
 * Auto-configuration of the Trust resource-server starter.
 *
 * Applied to every application that has this starter as a dependency.
 * Every bean is conditional: an application can declare its own to replace
 * the default behavior.
 * <p>
 * Running next to {@code trust-security-oauth2-client-starter} is only
 * possible in "multiple SecurityFilterChain" mode, declared on both sides
 * with two disjoint {@code multi-chain.request-pattern}; otherwise the
 * startup fails (see {@link MultiChainCoexistenceCondition}).
 * <p>
 * Packages:
 * <ul>
 *   <li>{@code authorities}: claims to authorities mapping;</li>
 *   <li>{@code authorization}: {@code @RequiresPermission};</li>
 *   <li>{@code jwt}: JWT decoder and multi-issuer mode;</li>
 *   <li>{@code tokenformat}: exclusive choice of JWT / opaque / multi-issuer;</li>
 *   <li>{@code multichain}: running next to the OAuth2 client starter.</li>
 * </ul>
 */
@AutoConfiguration
@EnableWebSecurity
@EnableMethodSecurity
@EnableConfigurationProperties({
        ResourceServerSecurityProperties.class,
        AuthoritiesMappingProperties.class,
        MultiChainProperties.class})
@Conditional(MultiChainCoexistenceCondition.class)
public class ResourceServerAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(ResourceServerAutoConfiguration.class);

    private static final String ACTUATOR_HEALTH_PATH = "/actuator/health";

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt", name = "issuer-uri")
    public JwtDecoder jwtDecoder(
            ResourceServerSecurityProperties properties,
            @Value("${spring.security.oauth2.resourceserver.jwt.issuer-uri}") String issuerUri) {
        return JwtDecoderFactory.create(issuerUri, properties.getClientId());
    }

    /**
     * Opaque-token counterpart of {@link #jwtDecoder(ResourceServerSecurityProperties, String)}:
     * activates purely on the presence of {@code spring.security.oauth2.resourceserver.opaquetoken.introspection-uri},
     * exactly as Spring Boot's own native opaque-token auto-configuration
     * does - no Trust-specific property introduces a second way to select
     * the token format. Built directly from the native properties, the same
     * style as {@link #jwtDecoder(ResourceServerSecurityProperties, String)}
     * delegating to {@link JwtDecoderFactory}, rather than depending on Spring
     * Boot's own auto-configured {@link OpaqueTokenIntrospector} bean - this
     * avoids two competing beans of the same type ever existing together.
     * <p>
     * Authorities are composed, never replaced, by {@link TrustOpaqueTokenIntrospector}
     * - the same {@code trust.security.authorities.mappings}-driven
     * {@link com.trust.security.core.role.ClaimAuthoritiesMapper} used for
     * JWT, applied here to the introspection response's attributes (same
     * {@code Map<String, Object>} shape as a JWT's claims).
     * <p>
     * <b>Naming trap to know about</b>: {@code spring.security.oauth2.resourceserver.opaquetoken.client-id}
     * (below) is the credential this resource server authenticates itself
     * with <em>to call the introspection endpoint</em> - unrelated to
     * {@code trust.security.resource-server.client-id} (the audience this
     * resource server expects <em>in</em> a token, {@link ResourceServerSecurityProperties#getClientId()}).
     * The two properties coexist and look alike; they answer different
     * questions. When the native property is absent, this factory falls back
     * to {@code trust.security.resource-server.client-id} - the common case
     * where a resource server introspects using its own identity - logged
     * once at {@code DEBUG} when it applies; an application whose
     * introspecting identity genuinely differs from its own audience (e.g. a
     * shared introspection service account) sets the native property
     * explicitly to override this fallback. A wrong assumption here fails
     * loudly (the introspection call itself is rejected by the authorization
     * server), never silently: this is a convenience default, not a security
     * decision.
     */
    @Bean
    @ConditionalOnMissingBean(OpaqueTokenIntrospector.class)
    @ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.opaquetoken", name = "introspection-uri")
    public OpaqueTokenIntrospector opaqueTokenIntrospector(
            ClaimAuthoritiesMapper claimAuthoritiesMapper,
            ResourceServerSecurityProperties properties,
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}") String introspectionUri,
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id:}") String introspectionClientId,
            @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret:}") String introspectionClientSecret) {

        String resolvedClientId = introspectionClientId.isBlank()
                ? properties.getClientId()
                : introspectionClientId;

        if (introspectionClientId.isBlank() && log.isDebugEnabled()) {
            log.debug("spring.security.oauth2.resourceserver.opaquetoken.client-id is not set - "
                    + "falling back to trust.security.resource-server.client-id ('{}') to "
                    + "authenticate to the introspection endpoint.", resolvedClientId);
        }

        OpaqueTokenIntrospector delegate = SpringOpaqueTokenIntrospector
                .withIntrospectionUri(introspectionUri)
                .clientId(resolvedClientId)
                .clientSecret(introspectionClientSecret)
                .build();

        return new TrustOpaqueTokenIntrospector(delegate, claimAuthoritiesMapper, properties.getClientId());
    }

    /**
     * Validates, once, that exactly one of {@link JwtDecoder}/{@link OpaqueTokenIntrospector}
     * is available - whether created by {@link #jwtDecoder(ResourceServerSecurityProperties, String)}/
     * {@link #opaqueTokenIntrospector(ClaimAuthoritiesMapper, ResourceServerSecurityProperties, String, String, String)}
     * or supplied directly by the application. Checked by bean presence
     * (via {@link ObjectProvider}), not by raw property text: an application
     * that supplies its own {@code JwtDecoder}/{@code OpaqueTokenIntrospector}
     * bean without ever mentioning the corresponding property must be
     * unaffected by this guard, exactly like every other bean in this class.
     * <p>
     * Without this guard: zero of either bean would silently leave Spring
     * Boot's own default {@code SecurityFilterChain} (HTTP Basic/form login)
     * in charge instead of Trust's; both at once would let bean-registration
     * order alone decide which of {@code jwtResourceServerFilterChain}/
     * {@code opaqueTokenResourceServerFilterChain} wins, silently. Neither is
     * acceptable for a security boundary - see {@link MissingTokenFormatException}
     * and {@link AmbiguousTokenFormatException}.
     */
    @Bean
    public TokenFormatGuard tokenFormatGuard(
            ObjectProvider<JwtDecoder> jwtDecoderProvider,
            ObjectProvider<OpaqueTokenIntrospector> opaqueTokenIntrospectorProvider,
            ObjectProvider<AuthenticationManagerResolver> authenticationManagerResolverProvider) {

        boolean hasJwt = jwtDecoderProvider.getIfAvailable() != null;
        boolean hasOpaque = opaqueTokenIntrospectorProvider.getIfAvailable() != null;
        boolean hasResolver = authenticationManagerResolverProvider.getIfAvailable() != null;

        if (hasResolver && (hasJwt || hasOpaque)) {
            throw new ConflictingResourceServerModeException(hasJwt, hasOpaque);
        }
        if (hasJwt && hasOpaque) {
            throw new AmbiguousTokenFormatException();
        }
        if (!hasJwt && !hasOpaque && !hasResolver) {
            throw new MissingTokenFormatException();
        }
        return new TokenFormatGuard();
    }

    /**
     * Multi-issuer JWT counterpart of {@link #jwtDecoder(ResourceServerSecurityProperties, String)}:
     * activates purely on {@code trust.security.resource-server.issuers} being
     * a non-empty list ({@link MultiIssuerConfiguredCondition}), and backs off
     * entirely - by raw {@link AuthenticationManagerResolver} type, since only
     * one concrete parameterization ({@code <HttpServletRequest>}) is ever
     * meaningful here - the moment an application supplies its own resolver
     * bean, exactly like every other bean in this class.
     * <p>
     * Reuses {@link JwtDecoderFactory}'s validators (issuer, audience,
     * expiry/not-before/clock skew) and the same {@code authoritiesConverter}
     * composite as the single-issuer mode, via {@link TrustIssuerAuthenticationManagerResolver} -
     * never Spring Security's own {@code JwtIssuerAuthenticationManagerResolver.fromTrustedIssuers(...)},
     * which would silently substitute Spring's default converter for Trust's.
     * See {@link TrustIssuerAuthenticationManagerResolver}'s Javadoc for the
     * full lazy-construction/caching/allowlist contract.
     */
    @Bean
    @ConditionalOnMissingBean(AuthenticationManagerResolver.class)
    @Conditional(MultiIssuerConfiguredCondition.class)
    public AuthenticationManagerResolver<HttpServletRequest> jwtIssuerAuthenticationManagerResolver(
            ResourceServerSecurityProperties properties,
            Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter) {

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);

        TrustIssuerAuthenticationManagerResolver perIssuerResolver = new TrustIssuerAuthenticationManagerResolver(
                properties.getIssuers(), properties.getClientId(), jwtConverter);

        return new JwtIssuerAuthenticationManagerResolver(perIssuerResolver);
    }

    @Bean
    @ConditionalOnMissingBean
    public ClaimAuthoritiesMapper claimAuthoritiesMapper(AuthoritiesMappingProperties properties) {
        return new ClaimAuthoritiesMapper(properties.getMappings());
    }

    /**
     * Composes Spring Security's own default {@link JwtGrantedAuthoritiesConverter}
     * (standard {@code SCOPE_*} authorities from the {@code scope}/{@code scp}
     * claim) with Trust's generic, configuration-driven {@link JwtClaimAuthoritiesConverter}
     * - rather than replacing the former with the latter. An application that
     * has not configured {@code trust.security.authorities.mappings} therefore
     * still gets the native scope-based authorities Spring Security would give
     * it without this starter, and Trust's mapped authorities (if any) are
     * added on top, deduplicated. An application supplying its own
     * {@code Converter<Jwt, Collection<GrantedAuthority>>} bean replaces this
     * composite entirely, as with every other bean in this class.
     */
    @Bean
    @ConditionalOnMissingBean
    public Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter(
            ResourceServerSecurityProperties properties,
            ClaimAuthoritiesMapper claimAuthoritiesMapper) {
        return new CompositeJwtGrantedAuthoritiesConverter(
                new JwtGrantedAuthoritiesConverter(),
                new JwtClaimAuthoritiesConverter(claimAuthoritiesMapper, properties.getClientId())
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public SecurityContextTaskDecorator securityContextTaskDecorator() {
        return new SecurityContextTaskDecorator();
    }

    /**
     * JWT/JWKS variant of the resource server filter chain - active only
     * when a {@link JwtDecoder} bean exists (Trust's own, from {@code jwt.issuer-uri},
     * or an application-supplied one). Mutually exclusive with
     * {@link #opaqueTokenResourceServerFilterChain}
     * fails startup rather than let both ever coexist. Mirrors the same
     * two-bean, two-condition pattern Spring Boot's own
     * {@code OAuth2ResourceServerWebSecurityAutoConfiguration} uses natively
     * for {@code jwtSecurityFilterChain}/{@code opaqueTokenSecurityFilterChain}.
     */
    @Bean
    @Conditional(NoForeignSecurityFilterChainCondition.class)
    @ConditionalOnBean(JwtDecoder.class)
    public SecurityFilterChain jwtResourceServerFilterChain(
            HttpSecurity http,
            ResourceServerSecurityProperties properties,
            MultiChainProperties multiChainProperties,
            Converter<Jwt, Collection<GrantedAuthority>> authoritiesConverter,
            @Qualifier("resourceServerAuthenticationEntryPoint")
            AuthenticationEntryPoint authenticationEntryPoint,
            @Qualifier("resourceServerAcrStepUpAccessDeniedHandler")
            AccessDeniedHandler accessDeniedHandler) throws Exception {

        JwtAuthenticationConverter jwtConverter = new JwtAuthenticationConverter();
        jwtConverter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);

        configureCommon(http, properties, multiChainProperties, authenticationEntryPoint, accessDeniedHandler)
                .oauth2ResourceServer(oauth2 ->
                        oauth2
                                .authenticationEntryPoint(authenticationEntryPoint)
                                .accessDeniedHandler(accessDeniedHandler)
                                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtConverter))
                );

        return http.build();
    }

    /**
     * Opaque-token/RFC 7662 variant - active only when an {@link OpaqueTokenIntrospector}
     * bean exists. See {@link #jwtResourceServerFilterChain} for the
     * mutual-exclusivity guarantee shared with this bean.
     */
    @Bean
    @Conditional(NoForeignSecurityFilterChainCondition.class)
    @ConditionalOnBean(OpaqueTokenIntrospector.class)
    public SecurityFilterChain opaqueTokenResourceServerFilterChain(
            HttpSecurity http,
            ResourceServerSecurityProperties properties,
            MultiChainProperties multiChainProperties,
            OpaqueTokenIntrospector introspector,
            @Qualifier("resourceServerAuthenticationEntryPoint")
            AuthenticationEntryPoint authenticationEntryPoint,
            @Qualifier("resourceServerAcrStepUpAccessDeniedHandler")
            AccessDeniedHandler accessDeniedHandler) throws Exception {

        configureCommon(http, properties, multiChainProperties, authenticationEntryPoint, accessDeniedHandler)
                .oauth2ResourceServer(oauth2 ->
                        oauth2
                                .authenticationEntryPoint(authenticationEntryPoint)
                                .accessDeniedHandler(accessDeniedHandler)
                                .opaqueToken(opaque -> opaque.introspector(introspector))
                );

        return http.build();
    }

    /**
     * Multi-issuer JWT variant - active whenever an {@link AuthenticationManagerResolver}
     * bean exists, whether it is {@link #jwtIssuerAuthenticationManagerResolver}
     * (Trust's own) or one the application supplied directly: this bean does
     * not distinguish the two, which <em>is</em> the documented back-off path
     * for an application needing custom precedence (e.g. a different
     * combination of resolvers). Mutually exclusive with {@link #jwtResourceServerFilterChain}/
     * {@link #opaqueTokenResourceServerFilterChain} by the same {@code @ConditionalOnMissingBean(SecurityFilterChain.class)}
     * guard, and with the single-issuer/opaque properties by {@link #tokenFormatGuard}.
     */
    @Bean
    @Conditional(NoForeignSecurityFilterChainCondition.class)
    @ConditionalOnBean(AuthenticationManagerResolver.class)
    public SecurityFilterChain multiIssuerResourceServerFilterChain(
            HttpSecurity http,
            ResourceServerSecurityProperties properties,
            MultiChainProperties multiChainProperties,
            AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver,
            @Qualifier("resourceServerAuthenticationEntryPoint")
            AuthenticationEntryPoint authenticationEntryPoint,
            @Qualifier("resourceServerAcrStepUpAccessDeniedHandler")
            AccessDeniedHandler accessDeniedHandler) throws Exception {

        configureCommon(http, properties, multiChainProperties, authenticationEntryPoint, accessDeniedHandler)
                .oauth2ResourceServer(oauth2 ->
                        oauth2
                                .authenticationEntryPoint(authenticationEntryPoint)
                                .accessDeniedHandler(accessDeniedHandler)
                                .authenticationManagerResolver(authenticationManagerResolver)
                );

        return http.build();
    }

    /**
     * Configuration shared by all token formats: optional multi-chain
     * scoping, stateless/CSRF-off, public paths, Problem Details exception
     * handling, and the MDC audit filter - everything that does not depend
     * on how the Bearer token is validated.
     * <p>
     * {@code .securityMatcher(...)} is only called when
     * {@code trust.security.resource-server.multi-chain.request-pattern} is
     * set - absent (the default, single-starter case), this chain applies to
     * every request. A request matching neither this starter's pattern nor the sibling
     * {@code trust-security-oauth2-client-starter}'s own pattern bypasses
     * Spring Security's filters entirely (native {@link org.springframework.security.web.FilterChainProxy}
     * behavior) - the two
     * patterns must together cover every path this application serves.
     */
    private HttpSecurity configureCommon(
            HttpSecurity http,
            ResourceServerSecurityProperties properties,
            MultiChainProperties multiChainProperties,
            AuthenticationEntryPoint authenticationEntryPoint,
            AccessDeniedHandler accessDeniedHandler) throws Exception {

        String[] publicPaths = Stream.concat(
                        properties.getPublicPaths().stream(),
                        Stream.of(ACTUATOR_HEALTH_PATH))
                .toArray(String[]::new);

        if (StringUtils.hasText(multiChainProperties.getRequestPattern())) {
            http.securityMatcher(multiChainProperties.getRequestPattern());
        }

        return http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(
                                SessionCreationPolicy.STATELESS
                        )
                )

                .authorizeHttpRequests(requests -> requests
                        .requestMatchers(publicPaths).permitAll()
                        .anyRequest().authenticated()
                )

                .exceptionHandling(exceptionHandling ->
                        exceptionHandling
                                .authenticationEntryPoint(
                                        authenticationEntryPoint
                                )
                                .accessDeniedHandler(
                                        accessDeniedHandler
                                )
                )
                .addFilterAfter(new AuthenticatedSubjectMdcFilter(),
                        BearerTokenAuthenticationFilter.class);
    }

    @Bean
    @ConditionalOnMissingBean
    public AcrAuthorization acrAuthorization() {
        return new AcrAuthorization();
    }

    /**
     * Named distinctly from the equivalent bean in {@code trust-security-oauth2-client-starter}:
     * both starters can run in the same application, and two beans with one
     * name would override each other.
     */
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnMissingBean(name = "resourceServerRequiresAcrAuthorizationInterceptor")
    public AuthorizationManagerBeforeMethodInterceptor resourceServerRequiresAcrAuthorizationInterceptor(
            AcrAuthorization acrAuthorization) {

        RequiresAcrAuthorizationManager authorizationManager =
                new RequiresAcrAuthorizationManager(acrAuthorization);

        return new AuthorizationManagerBeforeMethodInterceptor(
                new RequiresAcrPointcut(),
                authorizationManager
        );
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

    @Bean
    @ConditionalOnMissingBean
    public RequiresPermissionResolver requiresPermissionResolver() {
        return new RequiresPermissionResolver();
    }

    @Bean
    @ConditionalOnMissingBean
    public RequiresPermissionAuthorizationManager requiresPermissionAuthorizationManager(
            RequiresPermissionResolver permissionResolver,
            AuthorizationResourceIdResolver resourceIdResolver,
            PermissionContextProviderResolver contextProviderResolver,
            PermissionChecker permissionChecker) {

        return new RequiresPermissionAuthorizationManager(
                permissionResolver,
                resourceIdResolver,
                contextProviderResolver,
                permissionChecker
        );
    }


    @Bean
    @ConditionalOnMissingBean
    public AuthorizationResourceIdResolver authorizationResourceIdResolver() {
        return new AuthorizationResourceIdResolver();
    }


    @Bean
    @ConditionalOnMissingBean(PermissionContextProviderResolver.class)
    public PermissionContextProviderResolver permissionContextProviderResolver(
            ApplicationContext applicationContext) {

        return new SpringPermissionContextProviderResolver(
                applicationContext
        );
    }

    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    @ConditionalOnMissingBean(name = "requiresPermissionAuthorizationInterceptor")
    public AuthorizationManagerBeforeMethodInterceptor requiresPermissionAuthorizationInterceptor(
            RequiresPermissionResolver resolver,
            RequiresPermissionAuthorizationManager authorizationManager) {

        return new AuthorizationManagerBeforeMethodInterceptor(
                new RequiresPermissionPointcut(resolver),
                authorizationManager
        );
    }


    /**
     * No default {@link AuthorizationDecisionClient} is provided here: this
     * starter stays provider-neutral and only depends on the abstraction
     * from trust-security-core. An application that uses {@code @RequiresPermission}
     * supplies an adapter matching its identity provider's authorization
     * backend as a separate dependency (e.g. trust-security-keycloak-authorization-starter),
     * or defines its own {@link AuthorizationDecisionClient} bean directly.
     * <p>
     * This bean - and the whole {@code @RequiresPermission} method-security
     * subsystem it belongs to - is <b>always</b> created, whether or not such
     * a client is available: an application that only uses role-based
     * authorization ({@code @PreAuthorize}, {@code @RequiresAcr}) must not be
     * forced to supply an unused dependency. When no {@link AuthorizationDecisionClient}
     * is found, {@link ResourceServerPermissionChecker} runs in deny mode -
     * every {@code @RequiresPermission} check is refused, logged once at
     * {@code WARN} - rather than the subsystem becoming inert or, worse,
     * permissive. See {@link ResourceServerPermissionChecker}'s Javadoc for
     * the full behavior, including the fail-fast on more than one candidate
     * client.
     */
    @Bean
    @ConditionalOnMissingBean(PermissionChecker.class)
    public PermissionChecker permissionChecker(
            ObjectProvider<AuthorizationDecisionClient> authorizationDecisionClientProvider) {

        return new ResourceServerPermissionChecker(authorizationDecisionClientProvider);
    }

    @Bean
    @ConditionalOnMissingBean
    public ProblemDetailsWriter securityProblemDetailsWriter(
            ObjectMapper objectMapper) {

        return new ProblemDetailsWriter(
                objectMapper
        );
    }

    @Bean
    @ConditionalOnMissingBean(name = "resourceServerAuthenticationEntryPoint")
    public AuthenticationEntryPoint resourceServerAuthenticationEntryPoint(
            ProblemDetailsWriter problemDetailsWriter) {

        return new ProblemDetailsAuthenticationEntryPoint(
                new BearerTokenAuthenticationEntryPoint(),
                problemDetailsWriter
        );
    }

    @Bean
    @ConditionalOnMissingBean(name = "resourceServerAccessDeniedHandler")
    public AccessDeniedHandler resourceServerAccessDeniedHandler(
           ProblemDetailsWriter problemDetailsWriter) {

        return new ProblemDetailsAccessDeniedHandler(
                new BearerTokenAccessDeniedHandler(),
                problemDetailsWriter
        );
    }


    /**
     * Named distinctly from the equivalent bean in {@code trust-security-oauth2-client-starter},
     * for the same reason. Both sides
     * share the exact same {@link AcrStepUpAccessDeniedHandler} class for the
     * ACR-insufficient case (401 + {@code WWW-Authenticate}, identical in
     * both contexts) - only the fallback delegate for an unrelated
     * {@code AccessDeniedException} legitimately differs by starter
     * (Bearer-oriented here, session-oriented in the sibling starter).
     */
    @Bean
    @ConditionalOnMissingBean(name = "resourceServerAcrStepUpAccessDeniedHandler")
    public AccessDeniedHandler resourceServerAcrStepUpAccessDeniedHandler(
            @Qualifier("resourceServerAccessDeniedHandler")
            AccessDeniedHandler resourceServerAccessDeniedHandler,
            ProblemDetailsWriter problemDetailsWriter) {

        return new AcrStepUpAccessDeniedHandler(
                resourceServerAccessDeniedHandler,
                problemDetailsWriter
        );
    }

}