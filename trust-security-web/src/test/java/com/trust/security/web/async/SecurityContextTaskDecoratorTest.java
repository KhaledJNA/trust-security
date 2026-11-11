package com.trust.security.web.async;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Behavioral tests for {@link SecurityContextTaskDecorator}.
 * <p>
 * {@link org.springframework.core.task.TaskDecorator#decorate(Runnable)} is
 * called by Spring's executor on the SUBMITTING thread; the returned
 * {@code Runnable} later runs on a worker thread. These tests reproduce that
 * timing on a single test thread: capture context, mutate the thread's state
 * to simulate "a different worker thread", then run the decorated task.
 */
class SecurityContextTaskDecoratorTest {

    private final SecurityContextTaskDecorator decorator = new SecurityContextTaskDecorator();

    @AfterEach
    void clearContexts() {
        SecurityContextHolder.clearContext();
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void givenSecurityContextAtDecorationTime_whenTaskRuns_thenThatContextIsActiveDuringExecution() {
        SecurityContext capturedContext = SecurityContextHolder.createEmptyContext();
        capturedContext.setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of()));
        SecurityContextHolder.setContext(capturedContext);

        AtomicReference<SecurityContext> observed = new AtomicReference<>();
        Runnable decorated = decorator.decorate(() -> observed.set(SecurityContextHolder.getContext()));

        SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
        decorated.run();

        assertThat(observed.get().getAuthentication()).isSameAs(capturedContext.getAuthentication());
    }

    @Test
    void givenRequestAttributesAtDecorationTime_whenTaskRuns_thenTheyAreActiveDuringExecution() {
        RequestAttributes capturedAttributes = new ServletRequestAttributes(new MockHttpServletRequest());
        RequestContextHolder.setRequestAttributes(capturedAttributes);

        AtomicReference<RequestAttributes> observed = new AtomicReference<>();
        Runnable decorated = decorator.decorate(() -> observed.set(RequestContextHolder.getRequestAttributes()));

        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        decorated.run();

        assertThat(observed.get()).isSameAs(capturedAttributes);
    }

    @Test
    void givenNoRequestAttributesAtDecorationTime_whenTaskRuns_thenNoExceptionAndNoAttributesAreSet() {
        RequestContextHolder.resetRequestAttributes();

        AtomicReference<RequestAttributes> observed = new AtomicReference<>();
        Runnable decorated = decorator.decorate(() -> observed.set(RequestContextHolder.getRequestAttributes()));

        decorated.run();

        assertThat(observed.get()).isNull();
    }

    @Test
    void givenEmptySecurityContextAtDecorationTime_whenTaskRuns_thenNoExceptionAndAuthenticationIsNull() {
        SecurityContextHolder.clearContext();

        AtomicReference<Boolean> ran = new AtomicReference<>(false);
        Runnable decorated = decorator.decorate(() -> {
            assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
            ran.set(true);
        });

        decorated.run();

        assertThat(ran.get()).isTrue();
    }

    @Test
    void givenWorkerThreadHadAPriorSecurityContext_whenTaskFinishes_thenThatPriorContextIsRestored() {
        SecurityContext capturedContext = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(capturedContext);
        Runnable decorated = decorator.decorate(() -> { });

        SecurityContext workerPriorContext = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(workerPriorContext);

        decorated.run();

        assertThat(SecurityContextHolder.getContext()).isSameAs(workerPriorContext);
    }

    /** Covers a task run on the caller's own thread ({@code CallerRunsPolicy}). */
    @Test
    void givenWorkerThreadHadPriorRequestAttributes_whenTaskFinishes_thenTheyAreRestored() {
        Runnable decorated = decorator.decorate(() -> { });

        RequestAttributes workerPriorAttributes = new ServletRequestAttributes(new MockHttpServletRequest());
        RequestContextHolder.setRequestAttributes(workerPriorAttributes);

        decorated.run();

        assertThat(RequestContextHolder.getRequestAttributes()).isSameAs(workerPriorAttributes);
    }

    @Test
    void givenSubmittingThreadClearsItsAuthenticationAfterSubmit_whenTaskRuns_thenTaskStillSeesTheCaller() {
        SecurityContext callerContext = SecurityContextHolder.createEmptyContext();
        callerContext.setAuthentication(
                UsernamePasswordAuthenticationToken.authenticated("user-1", "credentials", List.of()));
        SecurityContextHolder.setContext(callerContext);
        AtomicReference<Object> observedPrincipal = new AtomicReference<>();
        Runnable decorated = decorator.decorate(() -> observedPrincipal.set(
                SecurityContextHolder.getContext().getAuthentication().getPrincipal()));

        callerContext.setAuthentication(null); // e.g. SecurityContextLogoutHandler
        decorated.run();

        assertThat(observedPrincipal.get()).isEqualTo("user-1");
    }

    @Test
    void givenTaskThrows_whenRunningDecoratedTask_thenContextIsStillRestoredAndExceptionPropagates() {
        SecurityContext capturedContext = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(capturedContext);
        Runnable decorated = decorator.decorate(() -> {
            throw new IllegalStateException("task failure");
        });

        SecurityContext workerPriorContext = SecurityContextHolder.createEmptyContext();
        SecurityContextHolder.setContext(workerPriorContext);

        assertThatThrownBy(decorated::run)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("task failure");

        assertThat(SecurityContextHolder.getContext()).isSameAs(workerPriorContext);
    }

    @Test
    void givenTwoTasksDecoratedWithDifferentContexts_whenBothRun_thenNeitherLeaksIntoTheOther() {
        SecurityContext contextA = SecurityContextHolder.createEmptyContext();
        contextA.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("alice", "pwd", List.of()));
        SecurityContextHolder.setContext(contextA);
        AtomicReference<SecurityContext> observedA = new AtomicReference<>();
        Runnable decoratedA = decorator.decorate(() -> observedA.set(SecurityContextHolder.getContext()));

        SecurityContext contextB = SecurityContextHolder.createEmptyContext();
        contextB.setAuthentication(UsernamePasswordAuthenticationToken.authenticated("bob", "pwd", List.of()));
        SecurityContextHolder.setContext(contextB);
        AtomicReference<SecurityContext> observedB = new AtomicReference<>();
        Runnable decoratedB = decorator.decorate(() -> observedB.set(SecurityContextHolder.getContext()));

        decoratedA.run();
        decoratedB.run();

        assertThat(observedA.get().getAuthentication()).isSameAs(contextA.getAuthentication());
        assertThat(observedB.get().getAuthentication()).isSameAs(contextB.getAuthentication());
    }
}
