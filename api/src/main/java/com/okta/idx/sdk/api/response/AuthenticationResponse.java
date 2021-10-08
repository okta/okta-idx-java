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
package com.okta.idx.sdk.api.response;

import com.okta.idx.sdk.api.client.Authenticator;
import com.okta.idx.sdk.api.client.ProceedContext;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.AuthenticatorEnrollments;
import com.okta.idx.sdk.api.model.ContextualData;
import com.okta.idx.sdk.api.model.CurrentAuthenticatorEnrollment;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.Idp;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.request.WebauthnRequest;

import java.util.LinkedList;
import java.util.List;

public class AuthenticationResponse {

    private TokenResponse tokenResponse;

    private ProceedContext proceedContext;

    private AuthenticationStatus authenticationStatus;

    private final List<String> errors = new LinkedList<>();

    private List<FormValue> formValues;

    private List<Authenticator> authenticators;

    private List<Idp> idps = new LinkedList<>();

    private ContextualData contextualData;

    public CurrentAuthenticatorEnrollment currentAuthenticator;

    public AuthenticatorEnrollments authenticatorEnrollments;

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

    public void addError(String error) {
        getErrors().add(error);
    }

    public List<FormValue> getFormValues() {
        return formValues;
    }

    public void setFormValues(List<FormValue> formValues) {
        this.formValues = formValues;
    }

    public List<Authenticator> getAuthenticators() {
        return authenticators;
    }

    public void setAuthenticators(List<Authenticator> authenticators) {
        this.authenticators = authenticators;
    }

    public List<Idp> getIdps() {
        return idps;
    }

    public void setIdps(List<Idp> idps) {
        this.idps = idps;
    }

    public ContextualData getContextualData() {
        return contextualData;
    }

    public void setContextualData(ContextualData contextualData) {
        this.contextualData = contextualData;
    }

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
}
