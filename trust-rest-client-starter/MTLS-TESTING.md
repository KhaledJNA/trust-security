# Testing mutual TLS locally

This walks through proving mutual TLS (mTLS) end-to-end on a laptop: a
server that requires a client certificate, a client presenting one via
`spring.http.serviceclient.<group>.ssl.bundle`, and confirmation that a
call without the right certificate genuinely fails while a call with it
genuinely succeeds. Nothing here needs a real partner sandbox - a local
self-signed certificate pair, generated with `keytool` (bundled with every
JDK), is enough to exercise the exact same code path.

This is not an automated test -
`ServiceClientWireCharacterizationTest.givenSslBundleConfigured_whenCallingAServerRequiringAClientCertificate_thenItPresentsOne`
in this module's test suite already does that, generating its own
certificates in a temporary directory on every run. This document is for a
developer who wants to see the mechanism with their own eyes, or reproduce
it against a real target.

## 1. Generate a certificate pair

Create a working directory and generate two independent identities: one for
a throwaway local "server" (standing in for the partner API), one for
"this application" (the client). Each side will only trust the other's
certificate, not any public certificate authority.

```bash
mkdir -p /tmp/mtls-demo && cd /tmp/mtls-demo

# The "server" - standing in for the partner API you're integrating with.
keytool -genkeypair -alias server -keyalg RSA -keysize 2048 -validity 30 \
    -keystore server.p12 -storetype PKCS12 -storepass changeit -keypass changeit \
    -dname "CN=localhost" -ext "SAN=dns:localhost,ip:127.0.0.1"
keytool -exportcert -alias server -keystore server.p12 -storetype PKCS12 \
    -storepass changeit -file server.cer

# "This application" - the identity the partner is expecting to see.
keytool -genkeypair -alias client -keyalg RSA -keysize 2048 -validity 30 \
    -keystore client.p12 -storetype PKCS12 -storepass changeit -keypass changeit \
    -dname "CN=trust-client"
keytool -exportcert -alias client -keystore client.p12 -storetype PKCS12 \
    -storepass changeit -file client.cer

# Each side trusts only the other's certificate.
keytool -importcert -alias server -file server.cer \
    -keystore client-truststore.p12 -storetype PKCS12 -storepass changeit -noprompt
keytool -importcert -alias client -file client.cer \
    -keystore server-truststore.p12 -storetype PKCS12 -storepass changeit -noprompt
```

You should now have five files: `server.p12`, `client.p12`,
`client-truststore.p12`, `server-truststore.p12`, plus the intermediate
`.cer` exports. `server.p12` and `server-truststore.p12` belong to the test
server below; `client.p12` and `client-truststore.p12` belong to the Spring
Boot application.

## 2. Start a server that requires a client certificate

The real partner API already does this - it's outside this starter's
concern. To reproduce it locally without standing up a full server, this
one-file JDK program is enough (no dependencies, run with `java
Server.java` on JDK 17+):

```java
// Server.java
import com.sun.net.httpserver.*;
import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.nio.file.*;
import java.security.KeyStore;

public class Server {
    public static void main(String[] args) throws Exception {
        char[] password = "changeit".toCharArray();

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(Path.of("server.p12"))) {
            keyStore.load(in, password);
        }
        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        try (var in = Files.newInputStream(Path.of("server-truststore.p12"))) {
            trustStore.load(in, password);
        }

        var keyManagerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, password);
        var trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        var sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 8443), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(sslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters sslParameters = getSSLContext().getDefaultSSLParameters();
                sslParameters.setNeedClientAuth(true); // the whole point: reject anyone with no certificate
                params.setSSLParameters(sslParameters);
            }
        });
        server.createContext("/ping", exchange -> {
            byte[] body = "pong".getBytes();
            exchange.sendResponseHeaders(200, body.length);
            try (var out = exchange.getResponseBody()) {
                out.write(body);
            }
        });
        server.start();
        System.out.println("Listening on https://127.0.0.1:8443 - requires a client certificate");
    }
}
```

```bash
java Server.java
```

Leave it running in this terminal.

## 3. Configure the Spring Boot application

In your application, point a bundle at the client
keystore/truststore generated in step 1, and reference it from the
group's native transport configuration:

```yaml
spring:
  ssl:
    bundle:
      jks:
        bank-mtls:
          key:
            alias: client
          keystore:
            location: file:/tmp/mtls-demo/client.p12
            password: changeit
            type: PKCS12
          truststore:
            location: file:/tmp/mtls-demo/client-truststore.p12
            password: changeit
            type: PKCS12
  http:
    serviceclient:
      ping:
        base-url: https://127.0.0.1:8443
        ssl:
          bundle: bank-mtls
```

Declare a matching `@HttpExchange` interface, imported as its own group:

```java
public interface PingClient {
    @GetExchange("/ping")
    String ping();
}
```

```java
@SpringBootApplication
@ImportHttpServices(types = PingClient.class, group = "ping")
public class MyApplication { /* ... */ }
```

## 4. Confirm both outcomes

**With the bundle configured** (as above), calling `pingClient.ping()`
should return `"pong"` - the same result the server logs would show as an
accepted, certificate-verified connection.

**Without it** - comment out `spring.http.serviceclient.ping.ssl.bundle` and
restart - the same call fails with a connection-level exception (typically
wrapping `SSLHandshakeException` or a broken pipe/EOF, depending on the
JDK and TLS version negotiated), because the server never completes the
handshake with a peer presenting no certificate.

**With the wrong bundle name** (a typo, or a bundle that isn't declared),
the application fails at startup, not at call time - `NoSuchSslBundleException`
surfaces immediately while Spring Boot's native
`PropertiesRestClientHttpServiceGroupConfigurer` builds the group's
`RestClient`, rather than being deferred to the first request - native
Spring Boot behavior, unrelated to this starter.

## 5. Clean up

Stop the `Server.java` process and delete `/tmp/mtls-demo` - none of this
is meant to be kept around; the automated test referenced above already
regenerates everything it needs on every run, in a JUnit-managed temporary
directory.
