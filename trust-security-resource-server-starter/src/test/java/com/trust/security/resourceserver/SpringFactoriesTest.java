package com.trust.security.resourceserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.diagnostics.FailureAnalyzer;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Spring Boot silently skips a FailureAnalyzer it cannot load: a stale class
 * name in {@code spring.factories} would only show up as a raw stack trace
 * at the next misconfigured startup.
 */
class SpringFactoriesTest {

    @Test
    void everyDeclaredFailureAnalyzerExists() throws IOException {
        Properties factories = PropertiesLoaderUtils.loadProperties(
                new ClassPathResource("META-INF/spring.factories"));
        List<String> analyzers = Arrays.stream(StringUtils.commaDelimitedListToStringArray(
                        factories.getProperty(FailureAnalyzer.class.getName())))
                .map(String::trim)
                .toList();

        assertThat(analyzers).isNotEmpty();
        for (String analyzer : analyzers) {
            assertThat(classExists(analyzer)).as(analyzer).isTrue();
        }
    }

    private static boolean classExists(String className) {
        try {
            return FailureAnalyzer.class.isAssignableFrom(Class.forName(className));
        } catch (ClassNotFoundException e) {
            return false;
        }
    }
}
