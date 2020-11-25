/*
 * Copyright 2014 Stormpath, Inc.
 * Modifications Copyright 2018 Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.sdk.impl.config;

import com.okta.commons.http.authc.DisabledAuthenticator;
import com.okta.commons.http.authc.RequestAuthenticator;
import com.okta.commons.http.config.HttpClientConfiguration;

import java.util.HashSet;
import java.util.Set;

/**
 * This class holds the default configuration properties.
 *
 * During application initialization all the properties found in the pre-defined locations that are
 * defined by the user will be added here in the order defined in {@link com.okta.sdk.impl.client.DefaultIDXClientBuilder}.
 * Unset values will use default values from {@code com/okta/sdk/config/okta.yaml}.
 *
 * @since 0.5.0
 */
public class ClientConfiguration extends HttpClientConfiguration {

    private String issuer;
    private String clientId;
    private String clientSecret;
    private Set<String> scopes = new HashSet<>();

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    @Override
    public RequestAuthenticator getRequestAuthenticator() {
        return new DisabledAuthenticator();
    }

    @Override
    public String getBaseUrl() {
        return getIssuer();
    }

    @Override
    public String toString() {
        return "ClientConfiguration {issuer=" + getBaseUrl() +
            ", clientId=" + getClientId() +
            ", clientSecret=" + "*****" +
            ", scopes=" + getScopes() + " }";
    }
}
