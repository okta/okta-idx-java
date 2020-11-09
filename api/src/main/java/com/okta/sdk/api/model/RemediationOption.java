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
package com.okta.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.okta.sdk.api.client.OktaIdentityEngineClient;
import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.request.CancelRequest;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.request.IdentifyRequest;
import com.okta.sdk.api.response.OktaIdentityEngineResponse;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class RemediationOption {

    /**
     * Ion spec rel member based around the (form structure)[https://ionspec.org/#form-structure] rules
     */
    private String[] rel;

    /**
     * Identifier for the remediation option
     */
    private String name;

    /**
     * HTTP Method to use for this remediation option.
     */
    private String method;

    /**
     * Href for the remediation option
     */
    private String href;

    private FormValue[] value;

    /**
     * Accepts Header for this remediation option.
     */
    private String accepts;

    /**
     * Allow you to continue the remediation with this option.
     *
     * @param client the {@link OktaIdentityEngineClient} instance
     * @param request the request to Okta Identity Engine
     * @return OktaIdentityEngineResponse the response from Okta Identity Engine
     *
     * @throws IllegalArgumentException MUST throw this exception when provided data does not contain all required data for the proceed call.
     * @throws ProcessingException when the proceed operation encountered an execution/processing error.
     */
    public OktaIdentityEngineResponse proceed(OktaIdentityEngineClient client, Object request) throws IllegalArgumentException, ProcessingException {
        //TODO: refactor this piece
        if (request != null) {
            if (request instanceof IdentifyRequest) return client.identify((IdentifyRequest) request);
            if (request instanceof ChallengeRequest) return client.challenge((ChallengeRequest) request);
            if (request instanceof AnswerChallengeRequest) return client.answerChallenge((AnswerChallengeRequest) request);
        }
        return null;
    }

    /**
     * Call this function once the `successWithInteractionCode is present. This
     * method uses the `successWithInteractionCode` property. This method will
     * call to the resulting `href` to exchange the `interaction_code` value
     * for an `access_token` object that can be used in future api calls.
     *
     * @return String the interaction code
     */
    public String interactionCode() {
        //TODO
        return null;
    }

    /**
     * Get all form values.
     *
     * @return array an array of FormValue
     */
    public FormValue[] form() {
        return value;
    }

    public String getName() {
        return name;
    }
}
