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
package com.okta.idx.sdk.api.client;

import java.util.Set;

public abstract class IDXClientBuilder {

    public static final String DEFAULT_CLIENT_ISSUER_PROPERTY_NAME = "okta.idx.issuer";
    public static final String DEFAULT_CLIENT_ID_PROPERTY_NAME = "okta.idx.clientId";
    public static final String DEFAULT_CLIENT_SECRET_PROPERTY_NAME = "okta.idx.clientSecret";
    public static final String DEFAULT_CLIENT_SCOPES_PROPERTY_NAME = "okta.idx.scopes";
    public static final String DEFAULT_CLIENT_REDIRECT_URI_PROPERTY_NAME = "okta.idx.redirectUri";
    public static final String DEFAULT_CLIENT_TESTING_DISABLE_HTTPS_CHECK_PROPERTY_NAME = "okta.testing.disableHttpsCheck";

    protected abstract IDXClientBuilder setIssuer(String issuer);

    protected abstract IDXClientBuilder setClientId(String clientId);

    protected abstract IDXClientBuilder setClientSecret(String clientSecret);

    protected abstract IDXClientBuilder setScopes(Set<String> scopes);

    protected abstract IDXClientBuilder setRedirectUri(String redirectUri);

    protected abstract IDXClient build();
}
