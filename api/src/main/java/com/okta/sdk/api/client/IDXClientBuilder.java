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
package com.okta.sdk.api.client;

import java.util.Set;

public interface IDXClientBuilder {

    String DEFAULT_CLIENT_ISSUER_PROPERTY_NAME = "okta.idx.issuer";
    String DEFAULT_CLIENT_ID_PROPERTY_NAME = "okta.idx.clientId";
    String DEFAULT_CLIENT_SECRET_PROPERTY_NAME = "okta.idx.clientSecret";
    String DEFAULT_CLIENT_SCOPES_PROPERTY_NAME = "okta.idx.scopes";
    String DEFAULT_CLIENT_TESTING_DISABLE_HTTPS_CHECK_PROPERTY_NAME = "okta.testing.disableHttpsCheck";

    IDXClientBuilder setIssuer(String issuer);

    IDXClientBuilder setClientId(String clientId);

    IDXClientBuilder setClientSecret(String clientSecret);

    IDXClientBuilder setScopes(Set<String> scopes);

    IDXClient build();
}
