package com.trust.security.core.authorization;

import org.springframework.security.core.Authentication;

import java.util.Map;

public interface PermissionChecker {

    boolean isAllowed(
            Authentication authentication,
            String resource,
            String scope,
            Map<String, String> context
    );
}