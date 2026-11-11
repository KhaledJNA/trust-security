package com.trust.security.resourceserver.test;

import com.trust.security.core.authorization.AuthorizationDecisionClient;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.testSecurityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Full annotation-driven demonstration: a JSON claim set becomes a real
 * {@code JwtAuthenticationToken} through the actual
 * {@code trust-security-resource-server-starter} auto-configuration - the
 * very same {@code Converter<Jwt, Collection<GrantedAuthority>>} bean a real
 * application boots - not a hand-rolled fake.
 * <pre>
 *   user.json (claims)
 *       -&gt; Jwt
 *       -&gt; real JwtClaimAuthoritiesConverter (from ResourceServerAutoConfiguration)
 *       -&gt; ROLE_USER
 *       -&gt; endpoint authorized
 * </pre>
 */
@SpringBootTest(
        classes = WithTrustJwtIntegrationTest.TestApp.class,
        webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "trust.security.resource-server.client-id=test-client",
        "trust.security.authorities.mappings[0].path=permissions.roles",
        "trust.security.authorities.mappings[0].prefix=ROLE_"
})
class WithTrustJwtIntegrationTest {

    @SpringBootApplication
    static class TestApp {

        @RestController
        static class UserOnlyController {

            @GetMapping("/user-only")
            @PreAuthorize("hasRole('USER')")
            String userOnly(@AuthenticationPrincipal Jwt jwt) {
                return jwt.getSubject() + ":" + jwt.getClaimAsString("preferred_username");
            }
        }

        // The two beans below are exactly what a real application must supply
        // itself (network JWT validation and the fine-grained PDP adapter) -
        // neither is exercised by this test, which only sets the
        // SecurityContext directly and never calls @RequiresPermission code.
        @Bean
        JwtDecoder jwtDecoder() {
            return mock(JwtDecoder.class);
        }

        @Bean
        AuthorizationDecisionClient authorizationDecisionClient() {
            return request -> false;
        }
    }

    @Autowired
    private MockMvc mockMvc;

    @Test
    @WithTrustJwt("user.json")
    void givenUserClaim_whenCallingProtectedEndpoint_thenTheRealMappingGrantsAccessAndClaimsAreReadable()
            throws Exception {
        mockMvc.perform(get("/user-only").with(testSecurityContext()))
                .andExpect(status().isOk())
                .andExpect(content().string("user-123:sample-user"));
    }

    @Test
    @WithTrustJwt("no-roles.json")
    void givenFixtureWithoutUserRole_whenCallingProtectedEndpoint_thenAccessIsDenied() throws Exception {
        mockMvc.perform(get("/user-only").with(testSecurityContext()))
                .andExpect(status().isForbidden());
    }

    @Test
    void givenNoAnnotation_whenCallingProtectedEndpoint_thenNoArtificialAuthenticationExistsAndAccessIsUnauthorized()
            throws Exception {
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();

        mockMvc.perform(get("/user-only"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @WithTrustJwt("user.json")
    void givenAnnotatedTest_whenInspectingSecurityContextDirectly_thenAGenuineJwtAuthenticationTokenIsPresent() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();

        assertThat(authentication).isNotNull();
        assertThat(authentication.getPrincipal()).isInstanceOf(Jwt.class);
        assertThat(((Jwt) authentication.getPrincipal()).getSubject()).isEqualTo("user-123");
    }

    @Test
    void afterEachTest_theSecurityContextIsClearedByTheFramework() {
        assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
    }
}
