package com.trust.security.core.acr;

import org.springframework.aop.support.StaticMethodMatcherPointcut;

import java.lang.reflect.Method;

public final class RequiresAcrPointcut extends StaticMethodMatcherPointcut {

    @Override
    public boolean matches(Method method, Class<?> targetClass) {
        return RequiresAcrResolver.resolve(method, targetClass) != null;
    }
}