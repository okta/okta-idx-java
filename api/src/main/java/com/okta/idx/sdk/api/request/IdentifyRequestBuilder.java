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
package com.okta.idx.sdk.api.request;

import com.okta.idx.sdk.api.model.Credentials;

public class IdentifyRequestBuilder {

    private String identifier;

    private Credentials credentials;

    private boolean rememberMe;

    private String stateHandle;

    public static IdentifyRequestBuilder builder() {
        return new IdentifyRequestBuilder();
    }

    public IdentifyRequestBuilder withIdentifier(String identifier) {
        this.identifier = identifier;
        return this;
    }

    public IdentifyRequestBuilder withCredentials(Credentials credentials) {
        this.credentials = credentials;
        return this;
    }

    public IdentifyRequestBuilder withRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
        return this;
    }

    public IdentifyRequestBuilder withStateHandle(String stateHandle) {
        this.stateHandle = stateHandle;
        return this;
    }

    public IdentifyRequest build() {
        return new IdentifyRequest(identifier, credentials, rememberMe, stateHandle);
    }
}
