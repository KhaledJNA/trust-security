package com.trust.restclient.fixture.wire;

import org.springframework.web.service.annotation.GetExchange;

/** Deliberately shares a group with {@link SharedGroupClientA}, to exercise the multi-interface startup warning. */
public interface SharedGroupClientB {

    @GetExchange("/b")
    String callB();
}
