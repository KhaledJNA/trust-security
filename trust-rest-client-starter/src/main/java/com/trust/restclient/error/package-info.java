/**
 * Turns a non-2xx response from a downstream service, called through a
 * {@link com.trust.restclient.ServiceClient}, into a Trust exception
 * carrying its RFC 9457 Problem Details payload when it sent one.
 */
@NullMarked
package com.trust.restclient.error;

import org.jspecify.annotations.NullMarked;
