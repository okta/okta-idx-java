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
package com.okta.idx.sdk.api.client;

import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.ErrorResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.stream.Collectors;

final class WrapperUtil {

    private static final Logger logger = LoggerFactory.getLogger(WrapperUtil.class);

    static AuthenticationResponse handleIllegalArgumentException(IllegalArgumentException e) {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        logger.error("Exception occurred", e);
        authenticationResponse.addError("The current flow is not supported. Please check your policy configuration.");
        return authenticationResponse;
    }

    /**
     * Helper to parse {@link ProcessingException} and populate {@link AuthenticationResponse}
     * with appropriate error messages.
     *
     * @param e the {@link ProcessingException} reference
     */
    static AuthenticationResponse handleProcessingException(ProcessingException e) {
        logger.error("Exception occurred", e);

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
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
        return authenticationResponse;
    }

    static void printRemediationOptions(IDXResponse idxResponse) {
        if (idxResponse != null && idxResponse.remediation() != null) {
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
            logger.debug("Remediation options: {}", Arrays.stream(remediationOptions)
                    .map(RemediationOption::getName)
                    .collect(Collectors.toList()));
        } else {
            logger.debug("Remediation options unavailable");
        }
    }

    static void printMessage(IDXResponse idxResponse) {
        if(idxResponse != null && idxResponse.getMessages() != null && idxResponse.getMessages().hasErrorValue()) {
            Arrays.stream(idxResponse.getMessages().getValue())
                    .forEach(messageValue -> logger.error(messageValue.getMessage()));
        }
    }

    static String getStateHandle(FormValue[] formValues) {
        if (formValues == null) {
            return null;
        }
        for (FormValue formValue : formValues) {
            if ("stateHandle".equals(formValue.name)) {
                return formValue.value.toString();
            }
        }
        return null;
    }
}
