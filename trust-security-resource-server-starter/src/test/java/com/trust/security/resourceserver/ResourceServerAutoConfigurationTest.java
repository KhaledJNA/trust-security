package com.trust.security.resourceserver;

import com.trust.security.core.acr.AcrAuthorization;
import com.trust.security.core.authorization.AuthorizationDecisionClient;
import com.trust.security.core.authorization.PermissionChecker;
import com.trust.security.core.role.ClaimAuthoritiesMapper;
import com.trust.security.core.user.CurrentAuthoritiesProvider;
import com.trust.security.core.user.CurrentUserProvider;
import com.trust.security.client.OAuth2ClientAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.FilteredClassLoader;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import tools.jackson.databind.ObjectMapper;

import java.util.Collection;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Verifies the wiring contract of {@link ResourceServerAutoConfiguration}
 * end-to-end (including the {@link SecurityFilterChain} bean, hence the
 * {@link WebApplicationContextRunner}) - not Spring Security's own DSL
 * behavior, only what Trust configures.
 * <p>
 * A stub {@link JwtDecoder} is always supplied: the real default one
 * performs an OIDC discovery HTTP call at construction time
 * ({@code JwtDecoders.fromIssuerLocation}), which must not happen in an
 * internal unit test. Supplying it also exercises the very
 * {@code @ConditionalOnMissingBean} override this bean relies on.
 * <p>
 * The shared runner filters out {@code OAuth2ClientAutoConfiguration} from
 * the classloader: {@code trust-security-oauth2-client-starter} is a real
 * test-scope Maven dependency of this module (needed by
 * {@link ResourceServerOAuth2ClientMultiChainTest} and
 * {@link ResourceServerKeycloakAuthorizationPrecedenceTest}'s sibling
 * concerns), so its classes are genuinely on this module's test classpath -
 * without this filter, every test here would trip the cohabitation guard
 * ({@code MultiChainCoexistenceCondition}), which checks classpath
 * presence and cannot otherwise distinguish "a real application dependency"
 * from "a fellow test class incidentally reachable from the same JVM".
 * {@link ResourceServerOAuth2ClientMultiChainTest} builds its own,
 * unfiltered runner specifically to exercise that real-dependency case.
 */
class ResourceServerAutoConfigurationTest {

    private static final String CLIENT_ID_PROPERTY =
            "trust.security.resource-server.client-id=sample-api";

    private final WebApplicationContextRunner contextRunner = new WebApplicationContextRunner()
            .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
            .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
            .withBean(JwtDecoder.class, () -> mock(JwtDecoder.class))
            .withBean(AuthorizationDecisionClient.class, () -> request -> true)
            .withBean(ObjectMapper.class, ObjectMapper::new)
            .withPropertyValues(CLIENT_ID_PROPERTY);

    @Test
    void givenStubJwtDecoderAndAuthorizationDecisionClient_whenContextStarts_thenItLoadsSuccessfully() {
        contextRunner.run(context -> assertThat(context).hasNotFailed());
    }

    @Test
    void whenContextStarts_thenDefaultAuthorizationAndUserBeansArePresent() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(ClaimAuthoritiesMapper.class);
            assertThat(context).hasSingleBean(AcrAuthorization.class);
            assertThat(context).hasSingleBean(CurrentUserProvider.class);
            assertThat(context).hasSingleBean(CurrentAuthoritiesProvider.class);
            assertThat(context).hasSingleBean(PermissionChecker.class);
            assertThat(context.getBean(PermissionChecker.class))
                    .isInstanceOf(com.trust.security.resourceserver.authorization.ResourceServerPermissionChecker.class);
        });
    }

    @Test
    void whenContextStarts_thenSecurityFilterChainAndJwtAuthoritiesConverterAreCreated() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(SecurityFilterChain.class);
            assertThat(context).hasSingleBean(Converter.class);
            assertThat(context.getBean(Converter.class))
                    .isInstanceOf(com.trust.security.resourceserver.authorities.CompositeJwtGrantedAuthoritiesConverter.class);
        });
    }

    @Test
    void givenPublicPathsConfigured_whenContextStarts_thenResourceServerSecurityPropertiesReflectThem() {
        contextRunner
                .withPropertyValues("trust.security.resource-server.public-paths[0]=/public/ping")
                .run(context -> {
                    ResourceServerSecurityProperties properties =
                            context.getBean(ResourceServerSecurityProperties.class);
                    assertThat(properties.getPublicPaths()).containsExactly("/public/ping");
                });
    }

    @Test
    void givenApplicationSuppliedCurrentUserProvider_whenContextStarts_thenTrustDefaultBacksOff() {
        CurrentUserProvider custom = Optional::empty;

        contextRunner
                .withBean(CurrentUserProvider.class, () -> custom)
                .run(context -> {
                    assertThat(context).hasSingleBean(CurrentUserProvider.class);
                    assertThat(context.getBean(CurrentUserProvider.class)).isSameAs(custom);
                });
    }

    /**
     * An application supplying its own authorities converter replaces
     * Trust's composite entirely - it must not be merged with either half of
     * it (Spring Security's default converter or Trust's own mapping).
     * <p>
     * Registered through a real {@code @Configuration} class (as a genuine
     * application would) rather than {@code contextRunner.withBean(Class, Supplier)}:
     * that shortcut registers the bean under the raw {@code Converter} type,
     * without the parameterized {@code Converter<Jwt, Collection<GrantedAuthority>>}
     * generic information the {@code @ConditionalOnMissingBean} on Trust's
     * own factory method matches against - it would not be seen as an
     * existing bean, and both would end up coexisting instead of the
     * application's replacing Trust's.
     */
    @Test
    void givenApplicationSuppliedAuthoritiesConverter_whenContextStarts_thenItIsUsedAloneInsteadOfTrustsComposite() {
        contextRunner
                .withUserConfiguration(CustomAuthoritiesConverterConfig.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(Converter.class);
                    assertThat(context.getBean(Converter.class))
                            .isSameAs(CustomAuthoritiesConverterConfig.CUSTOM_CONVERTER);
                });
    }

    @org.springframework.context.annotation.Configuration
    static class CustomAuthoritiesConverterConfig {

        static final Converter<Jwt, Collection<GrantedAuthority>> CUSTOM_CONVERTER = jwt -> java.util.Set.of();

        @org.springframework.context.annotation.Bean
        Converter<Jwt, Collection<GrantedAuthority>> customJwtAuthoritiesConverter() {
            return CUSTOM_CONVERTER;
        }
    }

    /**
     * This starter alone, no cohabitation involved: an application using only
     * this starter and redefining its own {@code SecurityFilterChain} must
     * keep working - the cohabitation guard added to {@link ResourceServerAutoConfiguration}
     * triggers on the presence of the OAuth2 client starter's class, never
     * on the presence of a {@code SecurityFilterChain} bean.
     */
    @Test
    void givenApplicationSuppliedSecurityFilterChain_whenContextStarts_thenTrustDefaultBacksOff() {
        SecurityFilterChain custom = mock(SecurityFilterChain.class);

        contextRunner
                .withBean(SecurityFilterChain.class, () -> custom)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context.getBean(SecurityFilterChain.class)).isSameAs(custom);
                });
    }

    @Test
    void givenApplicationSuppliedAuthorizationDecisionClient_whenContextStarts_thenItIsUsedByPermissionChecker() {
        AuthorizationDecisionClient custom = request -> false;

        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(JwtDecoder.class, () -> mock(JwtDecoder.class))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withBean(AuthorizationDecisionClient.class, () -> custom)
                .withPropertyValues(CLIENT_ID_PROPERTY)
                .run(context -> {
                    assertThat(context).hasSingleBean(AuthorizationDecisionClient.class);
                    assertThat(context.getBean(AuthorizationDecisionClient.class)).isSameAs(custom);
                    assertThat(context).hasNotFailed();
                });
    }

    /**
     * Locks the explicit, documented behavior when no {@link AuthorizationDecisionClient}
     * is available: the context still starts (an application that only uses
     * role-based authorization must not be forced to supply an unused
     * dependency), and the {@code @RequiresPermission} subsystem runs in deny
     * mode - every check refused - rather than becoming inert or permissive.
     * See the Javadoc on {@code ResourceServerAutoConfiguration.permissionChecker(...)}.
     */
    @Test
    void givenNoAuthorizationDecisionClientAvailable_whenContextStarts_thenItLoadsSuccessfullyWithPermissionCheckerInDenyMode() {
        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(JwtDecoder.class, () -> mock(JwtDecoder.class))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(CLIENT_ID_PROPERTY)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(AuthorizationDecisionClient.class);
                    assertThat(context).hasSingleBean(PermissionChecker.class);

                    PermissionChecker permissionChecker = context.getBean(PermissionChecker.class);
                    boolean allowed = permissionChecker.isAllowed(
                            org.springframework.security.authentication.UsernamePasswordAuthenticationToken
                                    .authenticated("user-1", "credentials", java.util.List.of()),
                            "Document",
                            "modify",
                            java.util.Map.of());

                    assertThat(allowed).isFalse();
                });
    }

    /**
     * Two {@link AuthorizationDecisionClient} beans wired at once is a
     * configuration error - not silently resolved by picking one - because
     * ResourceServerPermissionChecker resolves its (optional) client via
     * {@link org.springframework.beans.factory.ObjectProvider#getIfAvailable()},
     * which throws {@code NoUniqueBeanDefinitionException} (naming the
     * competing beans) rather than choosing arbitrarily.
     */
    @Test
    void givenMultipleAuthorizationDecisionClientBeans_whenContextStarts_thenItFailsFastNamingTheCandidates() {
        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(JwtDecoder.class, () -> mock(JwtDecoder.class))
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withBean("firstDecisionClient", AuthorizationDecisionClient.class, () -> request -> true)
                .withBean("secondDecisionClient", AuthorizationDecisionClient.class, () -> request -> false)
                .withPropertyValues(CLIENT_ID_PROPERTY)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(org.springframework.beans.factory.NoUniqueBeanDefinitionException.class)
                            .hasMessageContaining("firstDecisionClient")
                            .hasMessageContaining("secondDecisionClient");
                });
    }

    /**
     * Opaque-token counterpart of the JWT wiring test above: activates
     * purely on the native {@code opaquetoken.introspection-uri} property,
     * with no {@code spring.security.oauth2.resourceserver.opaquetoken.client-id}
     * set - exercising the fallback onto {@code trust.security.resource-server.client-id}
     * (the common case of a resource server introspecting with its own
     * identity, see {@code ResourceServerAutoConfiguration.opaqueTokenIntrospector}'s
     * Javadoc).
     */
    @Test
    void givenOpaqueTokenIntrospectionConfigured_whenContextStarts_thenOpaqueFilterChainIsCreated() {
        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(AuthorizationDecisionClient.class, () -> request -> true)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(
                        CLIENT_ID_PROPERTY,
                        "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=https://idp.example.com/introspect",
                        "spring.security.oauth2.resourceserver.opaquetoken.client-secret=secret")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(JwtDecoder.class);
                    assertThat(context).hasSingleBean(OpaqueTokenIntrospector.class);
                    assertThat(context.getBean(OpaqueTokenIntrospector.class))
                            .isInstanceOf(com.trust.security.resourceserver.authorities.TrustOpaqueTokenIntrospector.class);
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
                            .containsExactly("opaqueTokenResourceServerFilterChain");
                });
    }

    /**
     * Without this guard, this exact configuration would silently fall back
     * to Spring Boot's own default {@code SecurityFilterChain} (HTTP
     * Basic/form login) instead of failing - see {@code MissingTokenFormatException}.
     */
    @Test
    void givenNeitherJwtNorOpaqueConfigured_whenContextStarts_thenItFailsWithMissingTokenFormatException() {
        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(AuthorizationDecisionClient.class, () -> request -> true)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(CLIENT_ID_PROPERTY)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(com.trust.security.resourceserver.tokenformat.MissingTokenFormatException.class);
                });
    }

    /**
     * Without this guard, this exact configuration would let bean
     * registration order alone decide, silently, which of the two filter
     * chains wins - see {@code AmbiguousTokenFormatException}.
     */
    @Test
    void givenBothJwtAndOpaqueConfigured_whenContextStarts_thenItFailsWithAmbiguousTokenFormatException() {
        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(JwtDecoder.class, () -> mock(JwtDecoder.class))
                .withBean(AuthorizationDecisionClient.class, () -> request -> true)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(
                        CLIENT_ID_PROPERTY,
                        "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=https://idp.example.com/introspect",
                        "spring.security.oauth2.resourceserver.opaquetoken.client-secret=secret")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(com.trust.security.resourceserver.tokenformat.AmbiguousTokenFormatException.class);
                });
    }

    private static final String ISSUERS_PROPERTY =
            "trust.security.resource-server.issuers[0].issuer-uri=https://idp.example.com/realms/trust";

    /**
     * Multi-issuer mode creates no {@link JwtDecoder}/{@link OpaqueTokenIntrospector}
     * bean at all - only an {@code AuthenticationManagerResolver} - and no
     * network call happens at context-startup time (the resolver builds each
     * issuer's decoder lazily; see {@link MultiIssuerWireCharacterizationTest}
     * for the real-network proof).
     */
    @Test
    void givenIssuersConfigured_whenContextStarts_thenMultiIssuerFilterChainIsCreatedWithoutJwtOrOpaqueBeans() {
        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(AuthorizationDecisionClient.class, () -> request -> true)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(CLIENT_ID_PROPERTY, ISSUERS_PROPERTY)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(JwtDecoder.class);
                    assertThat(context).doesNotHaveBean(OpaqueTokenIntrospector.class);
                    assertThat(context).hasSingleBean(
                            org.springframework.security.authentication.AuthenticationManagerResolver.class);
                    assertThat(context.getBean(
                            org.springframework.security.authentication.AuthenticationManagerResolver.class))
                            .isInstanceOf(org.springframework.security.oauth2.server.resource.authentication
                                    .JwtIssuerAuthenticationManagerResolver.class);
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
                            .containsExactly("multiIssuerResourceServerFilterChain");
                });
    }

    /** Without this guard, both filter chains would individually be eligible - see {@code ConflictingResourceServerModeException}. */
    @Test
    void givenIssuersAndMonoIssuerJwtBothConfigured_whenContextStarts_thenItFailsWithConflictingResourceServerModeException() {
        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(JwtDecoder.class, () -> mock(JwtDecoder.class))
                .withBean(AuthorizationDecisionClient.class, () -> request -> true)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(CLIENT_ID_PROPERTY, ISSUERS_PROPERTY)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(com.trust.security.resourceserver.tokenformat.ConflictingResourceServerModeException.class);
                });
    }

    @Test
    void givenIssuersAndOpaqueBothConfigured_whenContextStarts_thenItFailsWithConflictingResourceServerModeException() {
        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(AuthorizationDecisionClient.class, () -> request -> true)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withPropertyValues(
                        CLIENT_ID_PROPERTY,
                        ISSUERS_PROPERTY,
                        "spring.security.oauth2.resourceserver.opaquetoken.introspection-uri=https://idp.example.com/introspect",
                        "spring.security.oauth2.resourceserver.opaquetoken.client-secret=secret")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                            .rootCause()
                            .isInstanceOf(com.trust.security.resourceserver.tokenformat.ConflictingResourceServerModeException.class);
                });
    }

    /**
     * An application-supplied {@code AuthenticationManagerResolver} bean - a
     * priori for its own unrelated multi-tenant needs - takes priority over
     * Trust's multi-issuer one, exactly like every other bean in this class;
     * {@code issuers} being configured at the same time is not treated as a
     * conflict (it is simply unused), consistent with how a JwtDecoder bean
     * already silently overrides the mono-issuer property elsewhere in this
     * starter.
     */
    @Test
    void givenApplicationSuppliedAuthenticationManagerResolver_whenContextStarts_thenTrustsDefaultBacksOff() {
        org.springframework.security.authentication.AuthenticationManagerResolver<jakarta.servlet.http.HttpServletRequest> custom =
                request -> authentication -> authentication;

        new WebApplicationContextRunner()
                .withClassLoader(new FilteredClassLoader(OAuth2ClientAutoConfiguration.class))
                .withConfiguration(AutoConfigurations.of(ResourceServerAutoConfiguration.class))
                .withBean(AuthorizationDecisionClient.class, () -> request -> true)
                .withBean(ObjectMapper.class, ObjectMapper::new)
                .withBean(
                        "customResolver",
                        org.springframework.security.authentication.AuthenticationManagerResolver.class,
                        () -> custom)
                .withPropertyValues(CLIENT_ID_PROPERTY, ISSUERS_PROPERTY)
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).hasSingleBean(
                            org.springframework.security.authentication.AuthenticationManagerResolver.class);
                    assertThat(context.getBean(
                            org.springframework.security.authentication.AuthenticationManagerResolver.class))
                            .isSameAs(custom);
                    assertThat(context).hasSingleBean(SecurityFilterChain.class);
                    assertThat(context.getBeanNamesForType(SecurityFilterChain.class))
                            .containsExactly("multiIssuerResourceServerFilterChain");
                });
    }
}
