package com.okta.sdk.client;

import java.util.Set;

public interface ClientBuilder {

    ClientBuilder setIssuer(String issuer);

    ClientBuilder setClientId(String clientId);

    ClientBuilder setScopes(Set<String> scopes);

    Client build();
}
