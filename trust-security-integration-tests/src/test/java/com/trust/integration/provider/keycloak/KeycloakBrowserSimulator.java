package com.trust.integration.provider.keycloak;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Drives the real Authorization Code flow against a real Keycloak the way a
 * browser would - following real redirects across origins, submitting the
 * real login form Keycloak serves - without a browser or HtmlUnit/Selenium:
 * plain JDK {@link HttpClient}, since Keycloak's login form is ordinary HTML
 * with a predictable {@code id="kc-form-login"}.
 * <p>
 * Cookies are tracked manually per origin, and redirects are followed
 * manually too (rather than using {@link java.net.CookieManager} and
 * {@link HttpClient.Redirect#NORMAL}): Keycloak's login flow cookies are
 * marked {@code Secure; SameSite=None} unconditionally (Keycloak's own
 * behavior, not specific to this environment), and both JDK mechanisms
 * correctly refuse, per spec, to ever send a {@code Secure} cookie back over
 * the plain {@code http://localhost} this suite deliberately uses. There is
 * no real browser trust boundary to protect here, only real Keycloak
 * endpoints - that protection is simply not relevant to what this test
 * simulator does.
 * <p>
 * This is deliberately the only place in the suite that knows Keycloak's
 * login page shape - contract tests only ever call {@link #loginViaKeycloak}
 * and then talk to the BFF harness normally.
 */
public final class KeycloakBrowserSimulator {

    private static final Pattern LOGIN_FORM_ACTION = Pattern.compile(
            "<form[^>]*id=\"kc-form-login\"[^>]*action=\"([^\"]+)\"");
    private static final Pattern COOKIE_NAME_VALUE = Pattern.compile("^([^=]+)=([^;]*)");
    private static final Pattern DELETED_COOKIE = Pattern.compile("(?i);\\s*Max-Age=0(;|$)");
    private static final Set<Integer> REDIRECT_STATUSES = Set.of(301, 302, 303, 307, 308);
    private static final int MAX_REDIRECTS = 10;

    private final HttpClient httpClient = HttpClient.newBuilder()
            .followRedirects(HttpClient.Redirect.NEVER)
            .build();

    private final Map<String, Map<String, String>> cookiesByOrigin = new ConcurrentHashMap<>();

    /**
     * Starts the login by hitting the BFF's own authorization endpoint (real
     * redirect to Keycloak, real discovery-driven authorization request),
     * submits real credentials to the real login form, and follows the real
     * redirect all the way back into the BFF - leaving this simulator's
     * cookie jar holding the BFF's real session cookie afterwards.
     */
    public HttpResponse<String> loginViaKeycloak(String bffBaseUrl, String registrationId, String username, String password)
            throws IOException, InterruptedException {

        HttpResponse<String> loginPage = get(bffBaseUrl + "/oauth2/authorization/" + registrationId);
        String actionUrl = fixMissingAuthority(extractLoginFormAction(loginPage.body()));

        String form = "username=" + encode(username) + "&password=" + encode(password);
        HttpResponse<String> afterLogin = execute(HttpRequest.newBuilder(URI.create(actionUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form)));

        // A successful login always ends the redirect chain back on the BFF's
        // own origin (its OAuth2 callback, then wherever its success handler
        // sends it next) - whatever that harness page returns (even a 404 for
        // a route it doesn't define) is the harness's concern, not this
        // login's. Still ending up on Keycloak's origin means the login itself
        // did not complete.
        if (origin(afterLogin.uri()).equals(origin(URI.create(actionUrl)))) {
            throw new IllegalStateException(
                    "Keycloak login flow did not leave the provider's origin - status "
                            + afterLogin.statusCode() + ": " + afterLogin.body());
        }
        return afterLogin;
    }

    /** GET following every redirect, as a browser address bar would. */
    public HttpResponse<String> get(String url) throws IOException, InterruptedException {
        return execute(HttpRequest.newBuilder(URI.create(url)).GET());
    }

    /**
     * Single GET, redirects <em>not</em> followed - to assert on a redirect
     * itself (its {@code Location}), e.g. the authorization request the BFF
     * sends the browser to. Cookies are still sent and stored.
     */
    public HttpResponse<String> getWithoutRedirect(String url, Map<String, String> headers)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url)).GET();
        headers.forEach(builder::header);
        return sendOnce(builder);
    }

    /** Single form POST, redirects not followed (e.g. a logout, whose redirect target is asserted). */
    public HttpResponse<String> postFormWithoutRedirect(String url, Map<String, String> headers, String form)
            throws IOException, InterruptedException {
        HttpRequest.Builder builder = HttpRequest.newBuilder(URI.create(url))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(form));
        headers.forEach(builder::header);
        return sendOnce(builder);
    }

    /** A cookie this jar currently holds for {@code url}'s origin. */
    public Optional<String> cookie(String url, String name) {
        return Optional.ofNullable(cookiesByOrigin.getOrDefault(origin(URI.create(url)), Map.of()).get(name));
    }

    /** Manual redirect loop (cross-origin, e.g. BFF -&gt; Keycloak -&gt; BFF), replaying this jar's cookies fresh for each hop's origin, exactly as a browser would. */
    private HttpResponse<String> execute(HttpRequest.Builder requestBuilder) throws IOException, InterruptedException {
        HttpRequest.Builder currentBuilder = requestBuilder;

        for (int redirect = 0; redirect < MAX_REDIRECTS; redirect++) {
            HttpResponse<String> response = sendOnce(currentBuilder);

            if (!REDIRECT_STATUSES.contains(response.statusCode())) {
                return response;
            }

            URI location = response.uri().resolve(response.headers().firstValue("Location")
                    .orElseThrow(() -> new IllegalStateException("Redirect without Location header: " + response)));
            currentBuilder = HttpRequest.newBuilder(location).GET();
        }
        throw new IllegalStateException("Too many redirects (>" + MAX_REDIRECTS + ")");
    }

    /** One request with this jar's cookies for its origin; cookies set by the response are stored. */
    private HttpResponse<String> sendOnce(HttpRequest.Builder builder) throws IOException, InterruptedException {
        URI targetUri = builder.build().uri();
        String cookieHeader = cookieHeaderFor(origin(targetUri));
        if (!cookieHeader.isEmpty()) {
            builder.setHeader("Cookie", cookieHeader);
        }
        HttpResponse<String> response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString());
        storeCookies(origin(response.uri()), response.headers().allValues("set-cookie"));
        return response;
    }

    private static String origin(URI uri) {
        return uri.getScheme() + "://" + uri.getAuthority();
    }

    private String cookieHeaderFor(String origin) {
        Map<String, String> cookies = cookiesByOrigin.getOrDefault(origin, Map.of());
        return cookies.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .collect(Collectors.joining("; "));
    }

    private void storeCookies(String origin, List<String> setCookieHeaders) {
        if (setCookieHeaders.isEmpty()) {
            return;
        }
        Map<String, String> cookies = cookiesByOrigin.computeIfAbsent(origin, ignored -> new ConcurrentHashMap<>());
        for (String header : setCookieHeaders) {
            Matcher matcher = COOKIE_NAME_VALUE.matcher(header);
            if (!matcher.find()) {
                continue;
            }
            // A deletion (Max-Age=0, as a logout sends) removes the cookie, as a browser would.
            if (DELETED_COOKIE.matcher(header).find()) {
                cookies.remove(matcher.group(1));
            } else {
                cookies.put(matcher.group(1), matcher.group(2));
            }
        }
    }

    /**
     * With {@code KC_PROXY_HEADERS=xforwarded} enabled (needed for the admin
     * client, see {@link KeycloakTestEnvironment}), Keycloak can build
     * absolute URLs for the login form action without the real mapped port
     * when no forwarded-port information is present, defaulting to the
     * scheme's standard port. The real, correct authority is known here
     * regardless (Keycloak's login page is always served from the same
     * host/port as the issuer), so it is restored rather than relying on
     * headers Keycloak may or may not honor consistently.
     */
    private static String fixMissingAuthority(String actionUrl) {
        URI uri = URI.create(actionUrl);
        if (uri.getPort() != -1) {
            return actionUrl;
        }
        URI correctBase = URI.create(KeycloakTestEnvironment.KEYCLOAK.getAuthServerUrl());
        String query = uri.getRawQuery() != null ? "?" + uri.getRawQuery() : "";
        return correctBase.getScheme() + "://" + correctBase.getAuthority() + uri.getRawPath() + query;
    }

    private static String extractLoginFormAction(String html) {
        Matcher matcher = LOGIN_FORM_ACTION.matcher(html);
        if (!matcher.find()) {
            throw new IllegalStateException(
                    "Keycloak login form (id=kc-form-login) not found - unexpected response, "
                            + "was the user already authenticated or the realm misconfigured? Body: " + html);
        }
        return matcher.group(1).replace("&amp;", "&");
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}
