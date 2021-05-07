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
package com.okta.idx.sdk.api.response;

import com.okta.idx.sdk.api.client.Authenticator;
import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.model.AuthenticationStatus;

import java.util.LinkedList;
import java.util.List;

public class AuthenticationResponse {

    private TokenResponse tokenResponse;

    private ProceedContext proceedContext;

    private AuthenticationStatus authenticationStatus;

    private List<String> errors = new LinkedList<>();

    private List<Authenticator> authenticators;

    public TokenResponse getTokenResponse() {
        return tokenResponse;
    }

    public void setTokenResponse(TokenResponse tokenResponse) {
        this.tokenResponse = tokenResponse;
    }

    public ProceedContext getProceedContext() {
        return proceedContext;
    }

    public void setProceedContext(ProceedContext proceedContext) {
        this.proceedContext = proceedContext;
    }

    public AuthenticationStatus getAuthenticationStatus() {
        return authenticationStatus;
    }

    public void setAuthenticationStatus(AuthenticationStatus authenticationStatus) {
        this.authenticationStatus = authenticationStatus;
    }

    public List<String> getErrors() {
        return errors;
    }

    public boolean addError(String error) {
        return getErrors().add(error);
    }

    public List<Authenticator> getAuthenticators() {
        return authenticators;
    }

    public void setAuthenticators(List<Authenticator> authenticators) {
        this.authenticators = authenticators;
    }
}
