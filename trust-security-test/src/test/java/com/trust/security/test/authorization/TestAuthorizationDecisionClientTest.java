package com.trust.security.test.authorization;

import com.trust.security.core.authorization.AuthorizationRequest;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class TestAuthorizationDecisionClientTest {

    private static AuthorizationRequest request(String resource, String action, Map<String, String> context) {
        return new AuthorizationRequest(
                new TestingAuthenticationToken("user-123", "n/a"),
                resource,
                action,
                context);
    }

    @Test
    void givenNoRuleConfigured_whenAsked_thenDeniedByDefault_failClosed() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient();

        boolean allowed = client.isAllowed(request("Document", "modify", Map.of()));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenPermitRuleForResourceAndAction_whenMatchingRequestAsked_thenAllowed() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .permit("Document", "modify");

        assertThat(client.isAllowed(request("Document", "modify", Map.of()))).isTrue();
    }

    @Test
    void givenDenyRule_whenMatchingRequestAsked_thenDenied() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .deny("Document", "modify");

        assertThat(client.isAllowed(request("Document", "modify", Map.of()))).isFalse();
    }

    @Test
    void givenPermitRuleForOneResource_whenAskedForAnotherResource_thenDeniedByDefault() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .permit("Document", "modify");

        assertThat(client.isAllowed(request("Attachment", "modify", Map.of()))).isFalse();
    }

    @Test
    void givenPermitRuleForOneAction_whenAskedForAnotherAction_thenDeniedByDefault() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .permit("Document", "modify");

        assertThat(client.isAllowed(request("Document", "read", Map.of()))).isFalse();
    }

    @Test
    void givenContextMatchingRule_whenContextMatches_thenAllowed() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .permit("Document", "modify", context -> "tenant-a".equals(context.get("tenant")));

        boolean allowed = client.isAllowed(request("Document", "modify", Map.of("tenant", "tenant-a")));

        assertThat(allowed).isTrue();
    }

    @Test
    void givenContextMatchingRule_whenContextDoesNotMatch_thenDeniedByDefault() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .permit("Document", "modify", context -> "tenant-a".equals(context.get("tenant")));

        boolean allowed = client.isAllowed(request("Document", "modify", Map.of("tenant", "tenant-b")));

        assertThat(allowed).isFalse();
    }

    @Test
    void givenRuleReconfiguredAfterAnEarlierOne_whenAsked_thenTheMostRecentRuleWins() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .permit("Document", "modify")
                .deny("Document", "modify");

        assertThat(client.isAllowed(request("Document", "modify", Map.of()))).isFalse();
    }

    @Test
    void whenAsked_thenTheAuthenticationFromTheRequestIsPreservedAndInspectable() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .permit("Document", "modify");
        Authentication authentication = new TestingAuthenticationToken("user-123", "n/a");

        client.isAllowed(new AuthorizationRequest(authentication, "Document", "modify", Map.of()));

        assertThat(client.lastRequest()).isPresent();
        assertThat(client.lastRequest().get().authentication()).isSameAs(authentication);
    }

    @Test
    void whenAsked_thenTheResourceActionAndContextAreInspectableViaLastRequest() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient();

        client.isAllowed(request("Document", "modify", Map.of("tenant", "tenant-a")));

        assertThat(client.lastRequest()).isPresent();
        assertThat(client.lastRequest().get().resource()).isEqualTo("Document");
        assertThat(client.lastRequest().get().action()).isEqualTo("modify");
        assertThat(client.lastRequest().get().context()).containsEntry("tenant", "tenant-a");
    }

    @Test
    void givenNoRequestAskedYet_whenInspectingLastRequest_thenItIsEmpty() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient();

        assertThat(client.lastRequest()).isEmpty();
    }

    @Test
    void givenRulesAndAHistory_whenReset_thenBothAreCleared() {
        TestAuthorizationDecisionClient client = new TestAuthorizationDecisionClient()
                .permit("Document", "modify");
        client.isAllowed(request("Document", "modify", Map.of()));

        client.reset();

        assertThat(client.lastRequest()).isEmpty();
        assertThat(client.isAllowed(request("Document", "modify", Map.of()))).isFalse();
    }
}
