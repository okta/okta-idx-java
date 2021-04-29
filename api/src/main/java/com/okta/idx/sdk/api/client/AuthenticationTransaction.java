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
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;

final class AuthenticationTransaction {
    static AuthenticationTransaction create(IDXClient client) throws ProcessingException {
        IDXClientContext idxClientContext = client.interact();
        Assert.notNull(idxClientContext, "IDX client context may not be null");

        IDXResponse introspectResponse = client.introspect(idxClientContext);
        String stateHandle = introspectResponse.getStateHandle();
        Assert.hasText(stateHandle, "State handle may not be null");

        RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();
        Util.printRemediationOptions(remediationOptions);

        return new AuthenticationTransaction(client, idxClientContext, introspectResponse);
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

    RemediationOption getRemediationOption(String name) {
        return Util.extractRemediationOption(idxResponse.remediation().remediationOptions(), name);
    }

    Optional<RemediationOption> getOptionalRemediationOption(String name) {
        return Util.extractOptionalRemediationOption(idxResponse.remediation().remediationOptions(), name);
    }

    String getStateHandle() {
        return idxResponse.getStateHandle();
    }

    IDXResponse getResponse() {
        return idxResponse;
    }

    AuthenticationTransaction proceed(Factory factory) throws ProcessingException {
        return new AuthenticationTransaction(client, clientContext, factory.create());
    }

    AuthenticationResponse asAuthenticationResponse() throws ProcessingException {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setIdxClientContext(clientContext);

        if (idxResponse.getMessages() != null) {
            Util.copyErrorMessages(idxResponse, authenticationResponse);
        }

        if (idxResponse.isLoginSuccessful()) {
            // login successful
            logger.info("Login Successful!");
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, clientContext);
            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
            authenticationResponse.setTokenResponse(tokenResponse);
        } else {
            // verify if password expired
            if (Util.isRemediationRequireCredentials(RemediationType.REENROLL_AUTHENTICATOR, idxResponse)) {
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.PASSWORD_EXPIRED);
            } else {
                String errMsg = "Unexpected remediation: " + RemediationType.REENROLL_AUTHENTICATOR;
                logger.error("{}", errMsg);
                Util.copyErrorMessages(idxResponse, authenticationResponse);
            }
        }

        return authenticationResponse;
    }
}
