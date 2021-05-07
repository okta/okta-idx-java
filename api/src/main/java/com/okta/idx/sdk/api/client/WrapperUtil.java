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

import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.ErrorResponse;
import com.okta.idx.sdk.api.response.NewUserRegistrationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;

final class WrapperUtil {

    private static final Logger logger = LoggerFactory.getLogger(WrapperUtil.class);

    /**
     * Helper to conditionally extract select authenticator enroll or authenticate
     * remediation option from {@link AuthenticationTransaction} reference.
     *
     * @param transaction      the authentication transaction reference
     * @return remediation option (either select auth enroll or select auth authenticate)
     */
    static RemediationOption getSelectAuthenticatorRemediationOption(AuthenticationTransaction transaction) {
        RemediationOption remediationOption = null;

        Optional<RemediationOption> selectAuthenticatorEnrollOptional =
                transaction.getOptionalRemediationOption(RemediationType.SELECT_AUTHENTICATOR_ENROLL);
        if (selectAuthenticatorEnrollOptional.isPresent()) {
            remediationOption = selectAuthenticatorEnrollOptional.get();
        }

        Optional<RemediationOption> selectAuthenticatorAuthenticateOptional =
                transaction.getOptionalRemediationOption(RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);
        if (selectAuthenticatorAuthenticateOptional.isPresent()) {
            remediationOption = selectAuthenticatorAuthenticateOptional.get();
        }

        return remediationOption;
    }

    /**
     * Helper to parse {@link ProcessingException} and populate {@link AuthenticationResponse}
     * with appropriate error messages.
     *
     * @param e the {@link ProcessingException} reference
     * @param authenticationResponse the {@link AuthenticationResponse} reference
     */
    static void handleProcessingException(ProcessingException e,
                                           AuthenticationResponse authenticationResponse) {
        logger.error("Exception occurred", e);
        ErrorResponse errorResponse = e.getErrorResponse();
        if (errorResponse != null) {
            if (errorResponse.getMessages() != null) {
                Arrays.stream(errorResponse.getMessages().getValue())
                        .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            } else {
                authenticationResponse.addError(errorResponse.getError() + ":" + errorResponse.getErrorDescription());
            }
        } else {
            authenticationResponse.addError(e.getMessage());
        }
        logger.error("Error Detail: {}", authenticationResponse.getErrors());
    }

    /**
     * Helper to parse {@link ProcessingException} and populate {@link NewUserRegistrationResponse}
     * with appropriate error messages.
     *
     * @param e the {@link ProcessingException} reference
     * @param newUserRegistrationResponse the {@link NewUserRegistrationResponse} reference
     */
    static void handleProcessingException(ProcessingException e,
                                          NewUserRegistrationResponse newUserRegistrationResponse) {
        logger.error("Exception occurred", e);
        ErrorResponse errorResponse = e.getErrorResponse();
        if (errorResponse != null) {
            if (errorResponse.getMessages() != null) {
                Arrays.stream(errorResponse.getMessages().getValue())
                        .forEach(msg -> newUserRegistrationResponse.addError(msg.getMessage()));
            } else {
                newUserRegistrationResponse.addError(errorResponse.getError() + ":" + errorResponse.getErrorDescription());
            }
        } else {
            newUserRegistrationResponse.addError(e.getMessage());
        }
        logger.error("Error Detail: {}", newUserRegistrationResponse.getErrors());
    }
}
