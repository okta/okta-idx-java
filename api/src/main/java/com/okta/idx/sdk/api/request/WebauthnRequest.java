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
package com.okta.idx.sdk.api.request;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class WebauthnRequest {

    public String clientData;
    public String attestation;
    public String authenticatorData;
    public String signatureData;

    public String getClientData() {
        return clientData;
    }

    public String getAttestation() {
        return attestation;
    }

    public String getAuthenticatorData() {
        return authenticatorData;
    }

    public String getSignatureData() {
        return signatureData;
    }
}
