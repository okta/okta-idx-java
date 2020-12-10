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

public class CancelRequestBuilder {

    private String stateHandle;

    public static CancelRequestBuilder builder() {
        return new CancelRequestBuilder();
    }

    public CancelRequestBuilder withStateHandle(String stateHandle) {
        this.stateHandle = stateHandle;
        return this;
    }

    public CancelRequest build() {
        return new CancelRequest(stateHandle);
    }
}
