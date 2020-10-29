package com.okta.sdk.impl.client;

import com.okta.commons.configcheck.ConfigurationValidator;
import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Collections;
import com.okta.sdk.api.client.Client;
import com.okta.sdk.api.client.ClientBuilder;

import java.util.Set;

public class DefaultClientBuilder implements ClientBuilder {

    private String issuer;

    private String clientId;

    private Set<String> scopes;

    @Override
    public ClientBuilder setIssuer(String issuer) {
        ConfigurationValidator.assertOrgUrl(issuer);
        this.issuer = issuer;
        return this;
    }

    @Override
    public ClientBuilder setClientId(String clientId) {
        Assert.notNull(clientId, "clientId cannot be null");
        this.clientId = clientId;
        return this;
    }

    @Override
    public ClientBuilder setScopes(Set<String> scopes) {
        Assert.isTrue(!Collections.isEmpty(scopes), "At least one scope is required");
        this.scopes = scopes;
        return this;
    }

    @Override
    public Client build() {
        this.validate();
        return new BaseClient(issuer, clientId, scopes);
    }

    private void validate() throws IllegalArgumentException {
        ConfigurationValidator.assertOrgUrl(issuer);
        Assert.notNull(clientId, "clientId cannot be null");
        Assert.isTrue(!Collections.isEmpty(scopes), "At least one scope is required");
    }
}
