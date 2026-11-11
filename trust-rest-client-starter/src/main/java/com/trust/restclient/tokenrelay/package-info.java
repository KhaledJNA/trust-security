/**
 * Resilience for acquiring the OAuth2 token relayed onto outgoing calls -
 * kept independent from an HTTP service group's own retry and circuit
 * breaker, since a struggling identity provider is not a signal about any
 * one downstream API's health.
 */
@NullMarked
package com.trust.restclient.tokenrelay;

import org.jspecify.annotations.NullMarked;
