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
package com.okta.idx.sdk.api.client;

import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Collections;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;
import java.util.Set;

final class AuthenticationTransaction {

    static AuthenticationTransaction create(IDXClient client) throws ProcessingException {
        IDXClientContext idxClientContext = client.interact();
        Assert.notNull(idxClientContext, "IDX client context may not be null");

        IDXResponse introspectResponse = client.introspect(idxClientContext);
        String stateHandle = introspectResponse.getStateHandle();
        Assert.hasText(stateHandle, "State handle may not be null");

        Util.printRemediationOptions(introspectResponse);

        return new AuthenticationTransaction(client, idxClientContext, introspectResponse);
    }

    static AuthenticationTransaction introspect(IDXClient client, IDXClientContext clientContext) throws ProcessingException {
        IDXResponse introspectResponse = client.introspect(clientContext);

        Util.printRemediationOptions(introspectResponse);

        return new AuthenticationTransaction(client, clientContext, introspectResponse);
    }

    interface Factory {
        IDXResponse create() throws ProcessingException;
    }

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationTransaction.class);

    private final IDXClient client;
    private final IDXClientContext clientContext;
    private final IDXResponse idxResponse;

    AuthenticationTransaction(IDXClient client, IDXClientContext clientContext, IDXResponse idxResponse) {
        this.client = client;
        this.clientContext = clientContext;
        this.idxResponse = idxResponse;
    }

    String getStateHandle() {
        return idxResponse.getStateHandle();
    }

    IDXResponse getResponse() {
        return idxResponse;
    }

    IDXClientContext getClientContext() {
        return clientContext;
    }

    RemediationOption getRemediationOption(String name) {
        Optional<RemediationOption> remediationOptionsOptional = getOptionalRemediationOption(name);
        Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + name);
        return remediationOptionsOptional.get();
    }

    RemediationOption getRemediationOption(String... names) {
        if (idxResponse == null || idxResponse.remediation() == null) {
            throw new IllegalArgumentException("Missing remediation option " + Arrays.toString(names));
        }
        Set<String> nameSet = Collections.toSet(names);
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(idxResponse.remediation().remediationOptions())
                .filter(x -> nameSet.contains(x.getName()))
                .findFirst();
        Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + Arrays.toString(names));
        return remediationOptionsOptional.get();
    }

    Optional<RemediationOption> getOptionalRemediationOption(String name) {
        if (idxResponse == null || idxResponse.remediation() == null) {
            return Optional.empty();
        }
        return Arrays.stream(idxResponse.remediation().remediationOptions())
                .filter(x -> name.equals(x.getName()))
                .findFirst();
    }

    boolean containsRemediationOption(String name) {
        return getOptionalRemediationOption(name).isPresent();
    }

    AuthenticationTransaction proceed(Factory factory) throws ProcessingException {
        IDXResponse idxResponse = factory.create();
        Util.printRemediationOptions(idxResponse);
        return new AuthenticationTransaction(client, clientContext, idxResponse);
    }

    AuthenticationResponse asAuthenticationResponse() throws ProcessingException {
        return asAuthenticationResponse(AuthenticationStatus.UNKNOWN);
    }

    AuthenticationResponse asAuthenticationResponse(AuthenticationStatus defaultStatus) throws ProcessingException {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setIdxClientContext(clientContext);

        copyErrorMessages(idxResponse, authenticationResponse);

        if (idxResponse.isLoginSuccessful()) {
            // login successful
            logger.info("Login Successful!");
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, clientContext);
            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
            authenticationResponse.setTokenResponse(tokenResponse);
        } else if (isRemediationRequireCredentials(RemediationType.REENROLL_AUTHENTICATOR)) {
            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.PASSWORD_EXPIRED);
        } else if (containsRemediationOption(RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE)) {
            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
        } else {
            authenticationResponse.setAuthenticationStatus(defaultStatus);
        }

        return authenticationResponse;
    }

    AuthenticationResponse asAuthenticationResponseExpecting(AuthenticationStatus status) {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setIdxClientContext(clientContext);

        copyErrorMessages(idxResponse, authenticationResponse);

        if (authenticationResponse.getErrors().isEmpty()) {
            authenticationResponse.setAuthenticationStatus(status);
        }

        return authenticationResponse;
    }

    boolean isRemediationRequireCredentials(String name) {
        if (idxResponse.remediation() == null) {
            return false;
        }

        Optional<RemediationOption> remediationOptionOptional = getOptionalRemediationOption(name);
        if (!remediationOptionOptional.isPresent()) {
            return false;
        }
        FormValue[] formValues = remediationOptionOptional.get().form();

        Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                .filter(x -> "credentials".equals(x.getName()))
                .findFirst();

        return credentialsFormValueOptional.isPresent();
    }

    private static void copyErrorMessages(IDXResponse idxResponse, AuthenticationResponse authenticationResponse) {
        if (idxResponse.getMessages() == null) {
            return;
        }
        Arrays.stream(idxResponse.getMessages().getValue())
                .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
    }
}
