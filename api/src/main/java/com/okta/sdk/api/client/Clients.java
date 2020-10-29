package com.okta.sdk.api.client;

import com.okta.commons.lang.Classes;

public final class Clients {

    /**
     * Returns a new {@link ClientBuilder} instance, used to construct {@link Client} instances.
     *
     * @return a new {@link ClientBuilder} instance, used to construct {@link Client} instances.
     */
    public static ClientBuilder builder() {
        return Classes.newInstance("com.okta.sdk.impl.client.DefaultClientBuilder");
    }
}
