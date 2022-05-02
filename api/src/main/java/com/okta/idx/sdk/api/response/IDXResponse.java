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

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.App;
import com.okta.idx.sdk.api.model.AuthenticatorEnrollments;
import com.okta.idx.sdk.api.model.Authenticators;
import com.okta.idx.sdk.api.model.Cancel;
import com.okta.idx.sdk.api.model.CurrentAuthenticatorEnrollment;
import com.okta.idx.sdk.api.model.Messages;
import com.okta.idx.sdk.api.model.Remediation;
import com.okta.idx.sdk.api.model.SuccessResponse;
import com.okta.idx.sdk.api.model.User;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class IDXResponse {

    private static final ObjectMapper objectMapper = new ObjectMapper()
        .enable(SerializationFeature.INDENT_OUTPUT)
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    /**
     * The stateHandle is used for all calls for the flow.
     */
    private String stateHandle;

    /**
     * The version that needs to be used in the headers
     */
    private String version;

    /**
     * When the current remediation flow expires
     */
    private String expiresAt;

    /**
     * The intent of the Okta Identity Engine flow
     */
    private String intent;

    private Remediation remediation;

    private Messages messages;

    private AuthenticatorEnrollments authenticatorEnrollments;

    private CurrentAuthenticatorEnrollment currentAuthenticatorEnrollment;

    private CurrentAuthenticatorEnrollment currentAuthenticator;

    private Authenticators authenticators;

    // TODO: model below objects (they are not used for processing anyway)?

/*
    currentAuthenticator
    recoveryAuthenticator
    enrollmentAuthenticator
    unenrollmentAuthenticator
    authenticatorChallenge
*/

    private User user;

    private App app;

    private SuccessResponse successWithInteractionCode;

    private Cancel cancel;

    /**
     * Return the current remediation object. MAY be null if there are no further remediation steps necessary
     *
     * @return Remediation|null
     */
    public Remediation remediation() {
        return this.remediation;
    }

    /**
     * The method to call when you want to cancel the Okta Identity Engine flow. This will return an IDXResponse
     *
     * @param client the {@link IDXClient} instance
     * @return IDXResponse
     * @throws ProcessingException when the cancel operation encountered an execution/processing error.
     */
    public IDXResponse cancel(IDXClient client) throws ProcessingException {
        return client.cancel(this.stateHandle);
    }

    /**
     * Return a success response object after `loginSuccess()` returns true.
     *
     * @return SuccessResponse
     */
    public SuccessResponse successWithInteractionCode() {
        return successWithInteractionCode;
    }

    /**
     * Check for the status of `successWithInteractionCode` indicating if the login was successful.
     *
     * @return boolean
     */
    public boolean isLoginSuccessful() {
        return successWithInteractionCode != null;
    }

    /**
     * Returns the raw JSON body of the Okta Identity Engine response.
     *
     * @return String
     * @throws JsonProcessingException json processing exception
     */
    public String raw() throws JsonProcessingException {
        return objectMapper.writeValueAsString(this);
    }

    public String getStateHandle() {
        return stateHandle;
    }

    public Messages getMessages() {
        return messages;
    }

    public AuthenticatorEnrollments getAuthenticatorEnrollments() {
        return authenticatorEnrollments;
    }

    public User getUser() {
        return user;
    }

    public Authenticators getAuthenticators() {
        return authenticators;
    }

    public CurrentAuthenticatorEnrollment getCurrentAuthenticatorEnrollment() { return currentAuthenticatorEnrollment; }

    public CurrentAuthenticatorEnrollment getCurrentAuthenticator() {
        return currentAuthenticator;
    }

    public SuccessResponse getSuccessWithInteractionCode() {
        return successWithInteractionCode;
    }
}
