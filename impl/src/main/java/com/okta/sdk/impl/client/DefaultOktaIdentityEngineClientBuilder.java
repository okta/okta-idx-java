/*
 * Copyright 2020-Present Okta, Inc.
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
package com.okta.sdk.impl.client;

import com.okta.commons.configcheck.ConfigurationValidator;
import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Collections;
import com.okta.sdk.api.client.OktaIdentityEngineClient;
import com.okta.sdk.api.client.OktaIdentityEngineClientBuilder;

import java.util.Set;

public class DefaultOktaIdentityEngineClientBuilder implements OktaIdentityEngineClientBuilder {

    private String issuer;

    private String clientId;

    private Set<String> scopes;

    @Override
    public OktaIdentityEngineClientBuilder setIssuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    @Override
    public OktaIdentityEngineClientBuilder setClientId(String clientId) {
        this.clientId = clientId;
        return this;
    }

    @Override
    public OktaIdentityEngineClientBuilder setScopes(Set<String> scopes) {
        this.scopes = scopes;
        return this;
    }

    @Override
    public OktaIdentityEngineClient build() {
        this.validate();
        return new BaseOktaIdentityEngineClient(issuer, clientId, scopes, null);
    }

    private void validate() throws IllegalArgumentException {
        ConfigurationValidator.assertOrgUrl(issuer);
        Assert.hasText(clientId, "clientId cannot be null");
        Assert.isTrue(!Collections.isEmpty(scopes), "At least one scope is required");
    }
}
