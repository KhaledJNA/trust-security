package com.trust.security.core.authorization;

import java.util.Map;

public interface PermissionContextProvider {

    Map<String, String> resolve(Object resourceId);
}