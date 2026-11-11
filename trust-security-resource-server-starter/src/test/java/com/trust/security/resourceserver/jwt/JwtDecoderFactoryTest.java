package com.trust.security.resourceserver.jwt;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderInitializationException;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Behavioral tests for the audience-validation contract {@link JwtDecoderFactory}
 * adds on top of Spring/Nimbus's own issuer-based decoding.
 * <p>
 * The decoding path of {@code create(...)} needs a real OIDC discovery call
 * and is covered by the integration tests; here only its laziness is
 * checked. The audience predicate Trust contributes is private, so it is
 * extracted via reflection to test it in isolation without a network call.
 */
class JwtDecoderFactoryTest {

    @SuppressWarnings("unchecked")
    private static OAuth2TokenValidator<Jwt> audienceValidator(String expectedAudience) throws Exception {
        Method method = JwtDecoderFactory.class.getDeclaredMethod("audienceValidator", String.class);
        method.setAccessible(true);
        return (OAuth2TokenValidator<Jwt>) method.invoke(null, expectedAudience);
    }

    private static Jwt jwtWithAudience(List<String> audience) {
        Jwt.Builder builder = Jwt.withTokenValue("token-value")
                .header("alg", "none")
                .claim("sub", "user-1")
                .issuedAt(Instant.EPOCH)
                .expiresAt(Instant.EPOCH.plusSeconds(3600));
        if (audience != null) {
            builder.claim("aud", audience);
        }
        return builder.build();
    }

    @Test
    void givenTokenAudienceMatchesExpectedAudience_whenValidating_thenNoErrors() throws Exception {
        OAuth2TokenValidator<Jwt> validator = audienceValidator("sample-api");

        OAuth2TokenValidatorResult result = validator.validate(jwtWithAudience(List.of("sample-api")));

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void givenTokenAudienceDoesNotMatchExpectedAudience_whenValidating_thenValidationFails() throws Exception {
        OAuth2TokenValidator<Jwt> validator = audienceValidator("sample-api");

        OAuth2TokenValidatorResult result = validator.validate(jwtWithAudience(List.of("other-api")));

        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void givenTokenHasNoAudienceClaim_whenValidating_thenValidationFails() throws Exception {
        OAuth2TokenValidator<Jwt> validator = audienceValidator("sample-api");

        OAuth2TokenValidatorResult result = validator.validate(jwtWithAudience(null));

        assertThat(result.hasErrors()).isTrue();
    }

    @Test
    void givenTokenHasMultipleAudiencesIncludingTheExpectedOne_whenValidating_thenNoErrors() throws Exception {
        OAuth2TokenValidator<Jwt> validator = audienceValidator("sample-api");

        OAuth2TokenValidatorResult result =
                validator.validate(jwtWithAudience(List.of("some-other-app", "sample-api")));

        assertThat(result.hasErrors()).isFalse();
    }

    @Test
    void givenAnUnreachableIssuer_whenCreating_thenNothingIsFetchedUntilTheFirstToken() {
        // Port 9 (discard): nothing listens there.
        JwtDecoder decoder = JwtDecoderFactory.create("http://127.0.0.1:9/realms/none", "sample-api");

        assertThatExceptionOfType(JwtDecoderInitializationException.class)
                .isThrownBy(() -> decoder.decode("token-value"));
    }
}
