/*
 * Copyright (c) 2020-Present, Okta, Inc.
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

import com.okta.idx.sdk.api.model.DeviceContext;

import java.util.Set;

abstract class IDXClientBuilder {

    protected abstract IDXClientBuilder setIssuer(String issuer);

    protected abstract IDXClientBuilder setClientId(String clientId);

    protected abstract IDXClientBuilder setClientSecret(String clientSecret);

    protected abstract IDXClientBuilder setScopes(Set<String> scopes);

    protected abstract IDXClientBuilder setRedirectUri(String redirectUri);

    protected abstract IDXClientBuilder setDeviceContext(DeviceContext deviceContext);

    protected abstract IDXClient build();
}
