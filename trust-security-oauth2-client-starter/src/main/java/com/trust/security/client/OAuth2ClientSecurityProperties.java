package com.trust.security.client;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

/**
 * Properties of the OAuth2 client (BFF) starter.
 *
 * The validation constraints fail the startup rather than let the error
 * show up at run time: a malformed origin silently blocks the front end, a
 * missing logout URL breaks the logout.
 */
@Validated
@ConfigurationProperties(prefix = "trust.security")
public class OAuth2ClientSecurityProperties {

    /**
     * Origins allowed to call this application from a browser (CORS). Each
     * must include the scheme: https://app.example.com, not app.example.com.
     */
    private List<@Pattern(regexp = "https?://.+",
            message = "must include the scheme (http:// or https://)") String> allowedOrigins = List.of();

    /** Application-specific public paths. */
    private List<String> publicPaths = List.of();

    /**
     * Where the browser lands once the logout is complete. Must be listed in
     * the client's valid post-logout redirect URIs at the identity provider.
     */
    @NotBlank(message = "trust.security.post-logout-redirect-uri is required")
    private String postLogoutRedirectUri;

    public List<String> getAllowedOrigins() {
        return allowedOrigins;
    }

    /**
     * Path of this application's local logout endpoint: a {@code POST} there
     * invalidates the local session, then starts the RP-initiated logout at
     * the provider's end-session endpoint, which redirects to
     * {@link #postLogoutRedirectUri}. Optional, {@code /logout} by default;
     * must not be blank when set.
     */
    @NotBlank
    private String logoutPath = "/logout";

    /**
     * Where a browser lands after a successful login that was not itself
     * triggered by an attempt to reach a specific protected resource - e.g.
     * a direct navigation to {@code /oauth2/authorization/{registrationId}},
     * with nothing to replay from {@code RequestCache}. Optional: {@code null}
     * by default, in which case {@code SavedRequestAwareAuthenticationSuccessHandler}
     * keeps its own native default ({@code /}, this application's own root).
     * <p>
     * Exists for exactly the same reason {@link #postLogoutRedirectUri} does:
     * a BFF whose own root is not a real page (a pure API backend, the UI
     * served separately by a SPA) needs to redirect the browser somewhere
     * that actually exists. Without this property, an application in that
     * shape had no declarative way to change this target - only a custom
     * {@code oauth2ClientAuthenticationSuccessHandler} bean of its own,
     * duplicating the step-up wiring this starter already provides
     * ({@link com.trust.security.client.stepup.AcrStepUpAuthenticationSuccessHandler}).
     * When a saved request *does* exist (the browser was denied access to a
     * specific protected URL before authenticating), that URL is still
     * replayed as before - this property only ever supplies the fallback.
     */
    private String postLoginRedirectUri;

    public String getPostLoginRedirectUri() {
        return postLoginRedirectUri;
    }

    public void setPostLoginRedirectUri(String postLoginRedirectUri) {
        this.postLoginRedirectUri = postLoginRedirectUri;
    }

    public void setAllowedOrigins(List<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    public List<String> getPublicPaths() {
        return publicPaths;
    }

    public void setPublicPaths(List<String> publicPaths) {
        this.publicPaths = publicPaths;
    }

    public String getPostLogoutRedirectUri() {
        return postLogoutRedirectUri;
    }

    public void setPostLogoutRedirectUri(String postLogoutRedirectUri) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
    }
    public String getLogoutPath() {
        return logoutPath;
    }

    public void setLogoutPath(String logoutPath) {
        this.logoutPath = logoutPath;
    }
}