/*
 * Copyright (c) 2021-Present, Okta, Inc.
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
package com.okta.idx.sdk.webauthn;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.okta.idx.sdk.api.model.AuthenticatorEnrollments;
import com.okta.idx.sdk.api.model.CurrentAuthenticatorEnrollment;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class WebauthnParams {

    private CurrentAuthenticatorEnrollment currentAuthenticator;

    private AuthenticatorEnrollments authenticatorEnrollments;

    private String webauthnCredentialId;

    public CurrentAuthenticatorEnrollment getCurrentAuthenticator() {
        return currentAuthenticator;
    }

    public void setCurrentAuthenticator(CurrentAuthenticatorEnrollment currentAuthenticator) {
        this.currentAuthenticator = currentAuthenticator;
    }

    public AuthenticatorEnrollments getAuthenticatorEnrollments() {
        return authenticatorEnrollments;
    }

    public void setAuthenticatorEnrollments(AuthenticatorEnrollments authenticatorEnrollments) {
        this.authenticatorEnrollments = authenticatorEnrollments;
    }

    public String getWebauthnCredentialId() {
        return webauthnCredentialId;
    }

    public void setWebauthnCredentialId(String webauthnCredentialId) {
        this.webauthnCredentialId = webauthnCredentialId;
    }
}
