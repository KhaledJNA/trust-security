/**
 * Circuit breaker protection for calls made through a
 * {@link com.trust.restclient.ServiceClient}: stops calling a downstream
 * service once it looks unhealthy, instead of letting every request keep
 * hitting it.
 */
@NullMarked
package com.trust.restclient.circuitbreaker;

import org.jspecify.annotations.NullMarked;
