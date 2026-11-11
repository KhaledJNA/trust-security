package com.trust.security.client.stepup;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

/**
 * Invalid {@code acr} or {@code returnTo} on {@code /oauth2/step-up}: a
 * client error, answered with 400 instead of the 500 a plain
 * {@link IllegalArgumentException} would produce.
 */
@ResponseStatus(HttpStatus.BAD_REQUEST)
public final class InvalidStepUpRequestException extends IllegalArgumentException {

    InvalidStepUpRequestException(String message) {
        super(message);
    }
}
