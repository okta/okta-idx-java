/*
 * Copyright 2021-Present Okta, Inc.
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
package com.okta.idx.sdk.api.model;

public class IDXClientContext {

    private String codeVerifier;

    private String interactionHandle;

    private String state;

    public IDXClientContext(String codeVerifier, String interactionHandle, String state) {
        this.codeVerifier = codeVerifier;
        this.interactionHandle = interactionHandle;
        this.state = state;
    }

    public String getCodeVerifier() {
        return codeVerifier;
    }

    public String getInteractionHandle() {
        return interactionHandle;
    }

    public String getState() {
        return state;
    }
}
