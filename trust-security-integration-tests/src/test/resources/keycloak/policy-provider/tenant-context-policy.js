// Deployed Keycloak Script Policy (Keycloak "Scripts" SPI - not the removed
// "upload JS via Admin API" feature). Reads the "tenant" attribute Trust's
// claim_token places in the UMA authorization request context
// (KeycloakAuthorizationDecisionClient -> claim_token), and grants only for
// TENANT_A - deliberately generic, no business/lab vocabulary.
var context = $evaluation.getContext();
var attributes = context.getAttributes();

if (!attributes.exists("tenant")) {
    $evaluation.deny();
} else {
    var tenant = attributes.getValue("tenant").asString(0);

    if (tenant == "TENANT_A") {
        $evaluation.grant();
    } else {
        $evaluation.deny();
    }
}
