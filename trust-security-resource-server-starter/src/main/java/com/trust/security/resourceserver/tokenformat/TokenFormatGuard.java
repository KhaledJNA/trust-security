package com.trust.security.resourceserver.tokenformat;

/**
 * No-op marker bean: its sole purpose is the validation performed by its own
 * {@code @Bean} factory method in {@code ResourceServerAutoConfiguration},
 * which throws {@link MissingTokenFormatException} or {@link AmbiguousTokenFormatException}
 * before this instance is ever returned. Nothing depends on it afterwards.
 */
public final class TokenFormatGuard {
}
