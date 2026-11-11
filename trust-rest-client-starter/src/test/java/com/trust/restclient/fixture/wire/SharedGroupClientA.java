package com.trust.restclient.fixture.wire;

import org.springframework.web.service.annotation.GetExchange;

/** Deliberately shares a group with {@link SharedGroupClientB}, to exercise the multi-interface startup warning. */
public interface SharedGroupClientA {

    @GetExchange("/a")
    String callA();
}
