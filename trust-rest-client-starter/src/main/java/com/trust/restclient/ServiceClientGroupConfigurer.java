package com.trust.restclient;

import com.trust.restclient.circuitbreaker.CircuitBreakerClientHttpRequestInterceptor;
import com.trust.restclient.correlation.CorrelationIdClientHttpRequestInterceptor;
import com.trust.restclient.error.ProblemDetailsResponseErrorHandler;
import com.trust.restclient.observation.ServiceClientRequestObservationConvention;
import com.trust.restclient.retry.NoRetryProcessor;
import com.trust.restclient.retry.RetryClientHttpRequestInterceptor;
import com.trust.restclient.tokenrelay.NoTokenRelay;
import com.trust.restclient.tokenrelay.NoTokenRelayProcessor;
import com.trust.restclient.tokenrelay.RetryingOAuth2AuthorizedClientManager;
import com.trust.restclient.tokenrelay.TrustAuthorizedClientManager;
import com.trust.restclient.tokenrelay.TrustPrincipalResolver;
import com.trust.restclient.tokenrelay.TrustClientRegistrationIdResolver;
import com.trust.web.problem.ProblemDetailsReader;
import io.github.resilience4j.circuitbreaker.CircuitBreakerRegistry;
import io.github.resilience4j.retry.RetryRegistry;
import io.micrometer.observation.ObservationRegistry;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.util.ClassUtils;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.annotation.ClientRegistrationId;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor;
import org.springframework.security.oauth2.client.web.client.OAuth2ClientHttpRequestInterceptor;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer;
import org.springframework.web.service.registry.HttpServiceGroup;
import tools.jackson.databind.ObjectMapper;

import java.lang.reflect.Method;
import java.util.stream.Collectors;

/**
 * Poses everything Trust adds on top of native HTTP service groups: token
 * relay, correlation, circuit breaker, retry, unified Problem Details
 * errors, and a per-group observation tag - applied by Spring's own
 * {@code HttpServiceGroupConfigurer} mechanism to every declared group,
 * alongside (not instead of) the native
 * {@code PropertiesRestClientHttpServiceGroupConfigurer} that wires
 * {@code spring.http.serviceclient.<group>.*} (URL, timeouts, TLS bundle).
 *
 * <h2>Interceptor order, and why no security property depends on it</h2>
 * <ol>
 *     <li>{@link com.trust.restclient.ResourceServerTokenRelayInterceptor} -
 *     relays the incoming JWT or opaque token in resource-server mode; abstains by reading
 *     the same request attribute {@code @ClientRegistrationId} populates,
 *     never by being overwritten (both interceptor orders produce
 *     identical results). Added only when the optional resource-server
 *     dependency is on the classpath - see
 *     {@link #RESOURCE_SERVER_PRESENT}.</li>
 *     <li>native {@code OAuth2ClientHttpRequestInterceptor} (only if an
 *     {@link OAuth2AuthorizedClientManager} bean exists) - presents a token
 *     for the registration {@link TrustClientRegistrationIdResolver}
 *     resolves, under the principal {@link TrustPrincipalResolver} resolves (a stable technical principal for a {@code client_credentials} registration, the real user's own {@code Authentication} for a {@code token-exchange} registration and for everything else); abstains (returns {@code null}) on its own terms when
 *     nothing applies, never by racing the interceptor above.</li>
 *     <li>{@link CorrelationIdClientHttpRequestInterceptor}.</li>
 *     <li>{@link CircuitBreakerClientHttpRequestInterceptor}, wrapping
 *     {@link RetryClientHttpRequestInterceptor} - the circuit breaker only
 *     sees the final, post-retry outcome, so a transient failure fixed by a
 *     retry never counts against the circuit.</li>
 * </ol>
 * Each of the two relay interceptors decides for itself, from information
 * already on the request (an attribute) or already in the security context
 * (the authentication type) - neither depends on the other having run
 * first, or on the order the four steps above are added in.
 */
public class ServiceClientGroupConfigurer implements RestClientHttpServiceGroupConfigurer {

    private static final Logger log = LoggerFactory.getLogger(ServiceClientGroupConfigurer.class);

    /**
     * {@code spring-boot-starter-security-oauth2-resource-server} is an
     * {@code optional} dependency of this starter:
     * a pure client application - a BFF relaying its own session token via
     * {@link TrustClientRegistrationIdResolver}, never itself a resource
     * server - legitimately omits it. {@link ResourceServerTokenRelayInterceptor}
     * can then never see a {@code JwtAuthenticationToken} (nothing on such a
     * classpath can ever produce one), so it is skipped entirely rather than
     * added and left to abstain at request time: an {@code instanceof} check
     * against an absent class throws {@code NoClassDefFoundError} the moment
     * the JVM resolves it on first invocation, which is on the very first
     * outgoing call, not at startup - demonstrated by execution.
     * <p>
     * Only {@code JwtAuthenticationToken} is checked here, even though
     * {@link ResourceServerTokenRelayInterceptor} also relays
     * {@code BearerTokenAuthentication} (opaque tokens, RFC 7662
     * introspection): both classes live in the same
     * {@code spring-security-oauth2-resource-server} artifact, so their
     * presence on the classpath is always simultaneous - one check
     * necessarily covers both branches.
     */
    private static final boolean RESOURCE_SERVER_PRESENT = ClassUtils.isPresent(
            "org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken",
            ServiceClientGroupConfigurer.class.getClassLoader());

    private final ServiceClientProperties properties;
    private final RetryRegistry retryRegistry;
    private final CircuitBreakerRegistry circuitBreakerRegistry;
    private final ObjectMapper objectMapper;
    private final ObservationRegistry observationRegistry;
    private final ObjectProvider<OAuth2AuthorizedClientManager> authorizedClientManagerProvider;
    private final ObjectProvider<ClientRegistrationRepository> clientRegistrationRepositoryProvider;
    private final ObjectProvider<OAuth2AuthorizedClientService> authorizedClientServiceProvider;

    public ServiceClientGroupConfigurer(
            ServiceClientProperties properties,
            RetryRegistry retryRegistry,
            CircuitBreakerRegistry circuitBreakerRegistry,
            ObjectMapper objectMapper,
            ObservationRegistry observationRegistry,
            ObjectProvider<OAuth2AuthorizedClientManager> authorizedClientManagerProvider,
            ObjectProvider<ClientRegistrationRepository> clientRegistrationRepositoryProvider,
            ObjectProvider<OAuth2AuthorizedClientService> authorizedClientServiceProvider) {
        this.properties = properties;
        this.retryRegistry = retryRegistry;
        this.circuitBreakerRegistry = circuitBreakerRegistry;
        this.objectMapper = objectMapper;
        this.observationRegistry = observationRegistry;
        this.authorizedClientManagerProvider = authorizedClientManagerProvider;
        this.clientRegistrationRepositoryProvider = clientRegistrationRepositoryProvider;
        this.authorizedClientServiceProvider = authorizedClientServiceProvider;
    }

    @Override
    public void configureGroups(Groups<RestClient.Builder> groups) {
        OAuth2AuthorizedClientManager manager = authorizedClientManagerProvider.getIfAvailable();
        ClientRegistrationRepository clientRegistrationRepository = clientRegistrationRepositoryProvider.getIfAvailable();
        OAuth2AuthorizedClientService authorizedClientService = authorizedClientServiceProvider.getIfAvailable();

        groups.forEachGroup((group, clientBuilder, proxyFactoryBuilder) -> {
            validateClientRegistrationIds(group, manager, clientRegistrationRepository);
            warnIfGroupHasMultipleInterfaces(group);

            String groupName = group.name();

            if (RESOURCE_SERVER_PRESENT) {
                clientBuilder.requestInterceptor(new ResourceServerTokenRelayInterceptor());
            }
            if (manager != null) {
                clientBuilder.requestInterceptor(oauth2ClientHttpRequestInterceptor(
                        manager, clientRegistrationRepository, authorizedClientService));
            }
            clientBuilder.requestInterceptor(new CorrelationIdClientHttpRequestInterceptor());

            if (properties.circuitBreakerFor(groupName).isEnabled()) {
                clientBuilder.requestInterceptor(circuitBreakerInterceptor(groupName));
            }
            if (properties.retryFor(groupName).isEnabled()) {
                clientBuilder.requestInterceptor(retryInterceptor(groupName));
            }

            clientBuilder.defaultStatusHandler(
                    new ProblemDetailsResponseErrorHandler(new ProblemDetailsReader(objectMapper)));
            clientBuilder.observationRegistry(observationRegistry);
            clientBuilder.observationConvention(new ServiceClientRequestObservationConvention(groupName));

            proxyFactoryBuilder.httpRequestValuesProcessor(ClientRegistrationIdProcessor.DEFAULT_INSTANCE);
            proxyFactoryBuilder.httpRequestValuesProcessor(NoRetryProcessor.INSTANCE);
            proxyFactoryBuilder.httpRequestValuesProcessor(NoTokenRelayProcessor.INSTANCE);
        });
    }

    private OAuth2ClientHttpRequestInterceptor oauth2ClientHttpRequestInterceptor(
            OAuth2AuthorizedClientManager manager, @Nullable ClientRegistrationRepository clientRegistrationRepository,
            @Nullable OAuth2AuthorizedClientService authorizedClientService) {

        OAuth2AuthorizedClientManager resolvedManager = manager;
        ServiceClientProperties.TokenAcquisitionRetryProperties retry = properties.getTokenAcquisitionRetry();
        if (retry.isEnabled()) {
            resolvedManager = new RetryingOAuth2AuthorizedClientManager(
                    manager, retryRegistry, retry.getMaxAttempts(), retry.getWaitDuration());
        }
        OAuth2ClientHttpRequestInterceptor interceptor = new OAuth2ClientHttpRequestInterceptor(resolvedManager);
        interceptor.setClientRegistrationIdResolver(new TrustClientRegistrationIdResolver());
        interceptor.setPrincipalResolver(new TrustPrincipalResolver(clientRegistrationRepository));
        if (authorizedClientService != null) {
            interceptor.setAuthorizationFailureHandler(
                    OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(authorizedClientService));
        }
        return interceptor;
    }

    private ClientHttpRequestInterceptor circuitBreakerInterceptor(String groupName) {
        ServiceClientProperties.CircuitBreakerProperties circuitBreaker = properties.circuitBreakerFor(groupName);
        return new CircuitBreakerClientHttpRequestInterceptor(
                circuitBreakerRegistry,
                groupName,
                circuitBreaker.getFailureRateThreshold(),
                circuitBreaker.getSlidingWindowSize(),
                circuitBreaker.getMinimumNumberOfCalls(),
                circuitBreaker.getWaitDurationInOpenState(),
                circuitBreaker.getPermittedNumberOfCallsInHalfOpenState());
    }

    private ClientHttpRequestInterceptor retryInterceptor(String groupName) {
        ServiceClientProperties.RetryProperties retry = properties.retryFor(groupName);
        return new RetryClientHttpRequestInterceptor(
                retryRegistry, groupName, retry.getMaxAttempts(), retry.getWaitDuration(),
                retry.getRetryableStatusCodes());
    }

    /**
     * Fails startup, naming the interface (and method, if that is where the
     * annotation is) and the registration in question, rather than let a
     * declared registration silently go unauthorized or unresolved at
     * request time.
     */
    private void validateClientRegistrationIds(
            HttpServiceGroup group, @Nullable OAuth2AuthorizedClientManager manager,
            @Nullable ClientRegistrationRepository clientRegistrationRepository) {

        for (Class<?> serviceType : group.httpServiceTypes()) {
            boolean typeNoTokenRelay = AnnotatedElementUtils.hasAnnotation(serviceType, NoTokenRelay.class);
            ClientRegistrationId typeLevel = AnnotatedElementUtils.findMergedAnnotation(serviceType, ClientRegistrationId.class);
            if (typeLevel != null) {
                validateOne(describe(serviceType, null), typeLevel, typeNoTokenRelay, manager, clientRegistrationRepository);
            }
            for (Method method : serviceType.getMethods()) {
                boolean noTokenRelay = typeNoTokenRelay || AnnotatedElementUtils.hasAnnotation(method, NoTokenRelay.class);
                ClientRegistrationId methodLevel = AnnotatedElementUtils.findMergedAnnotation(method, ClientRegistrationId.class);
                if (methodLevel != null) {
                    validateOne(describe(serviceType, method), methodLevel, noTokenRelay, manager, clientRegistrationRepository);
                } else if (typeLevel != null && noTokenRelay && !typeNoTokenRelay) {
                    // @ClientRegistrationId on the interface, @NoTokenRelay on this method only.
                    validateOne(describe(serviceType, method), typeLevel, true, manager, clientRegistrationRepository);
                }
            }
        }
    }

    private void validateOne(
            String where, ClientRegistrationId annotation, boolean noTokenRelay,
            @Nullable OAuth2AuthorizedClientManager manager,
            @Nullable ClientRegistrationRepository clientRegistrationRepository) {

        String registrationId = annotation.registrationId();

        if (manager == null) {
            throw new IllegalStateException(
                    ("%s is annotated @ClientRegistrationId(\"%s\"), but no OAuth2AuthorizedClientManager bean is "
                            + "declared in this application - a call declared to use a registration cannot be "
                            + "authorized without one. Declare an OAuth2AuthorizedClientManager bean, or remove "
                            + "the annotation if this call should relay the incoming user's own token instead.")
                            .formatted(where, registrationId));
        }

        ClientRegistration registration = clientRegistrationRepository != null
                ? clientRegistrationRepository.findByRegistrationId(registrationId) : null;

        if (clientRegistrationRepository != null && registration == null) {
            throw new IllegalStateException(
                    ("%s is annotated @ClientRegistrationId(\"%s\"), but no such registration exists under "
                            + "spring.security.oauth2.client.registration.%s - check the registration id for a typo.")
                            .formatted(where, registrationId, registrationId));
        }

        if (manager instanceof TrustAuthorizedClientManager
                && registration != null
                && !TrustAuthorizedClientManager.SUPPORTED_GRANT_TYPES.contains(registration.getAuthorizationGrantType())) {
            throw new IllegalStateException(
                    ("%s is annotated @ClientRegistrationId(\"%s\"), whose grant type is '%s' - Trust's default "
                            + "OAuth2AuthorizedClientManager only supports client_credentials and token-exchange "
                            + "(%s). Declare your own OAuth2AuthorizedClientManager bean to authorize this grant type.")
                            .formatted(where, registrationId, registration.getAuthorizationGrantType().getValue(),
                                    AuthorizationGrantType.TOKEN_EXCHANGE.getValue()));
        }

        // A token-exchange token is issued for the current user: sending it contradicts
        // @NoTokenRelay's "the target must not learn who is calling".
        if (noTokenRelay
                && registration != null
                && AuthorizationGrantType.TOKEN_EXCHANGE.equals(registration.getAuthorizationGrantType())) {
            throw new IllegalStateException(
                    ("%s is annotated both @NoTokenRelay and @ClientRegistrationId(\"%s\"), a token-exchange "
                            + "registration - the exchanged token still identifies the current user, which "
                            + "@NoTokenRelay forbids. Remove one of the two, or use a client_credentials registration.")
                            .formatted(where, registrationId));
        }
    }

    private static String describe(Class<?> serviceType, @Nullable Method method) {
        return method != null ? serviceType.getName() + "#" + method.getName() : serviceType.getName();
    }

    private void warnIfGroupHasMultipleInterfaces(HttpServiceGroup group) {
        if (group.httpServiceTypes().size() > 1 && log.isWarnEnabled()) {
            log.warn("HTTP service group '{}' contains {} interfaces ({}): they share a single circuit breaker, "
                            + "retry budget, and set of metrics. Give each interface its own group "
                            + "(@ImportHttpServices(group=...)) unless sharing them is intentional.",
                    group.name(), group.httpServiceTypes().size(),
                    group.httpServiceTypes().stream().map(Class::getSimpleName).collect(Collectors.joining(", ")));
        }
    }
}
