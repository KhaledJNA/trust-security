/**
 * Retry on transient failures for calls made through a
 * {@link com.trust.restclient.ServiceClient}, with a per-method opt-out
 * ({@link com.trust.restclient.retry.NoRetry}) for calls whose side effects
 * are not safe to duplicate.
 */
@NullMarked
package com.trust.restclient.retry;

import org.jspecify.annotations.NullMarked;
