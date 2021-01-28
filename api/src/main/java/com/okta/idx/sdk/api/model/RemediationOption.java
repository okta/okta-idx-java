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
package com.okta.idx.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.ChallengeRequest;
import com.okta.idx.sdk.api.request.EnrollRequest;
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequest;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.RecoverRequest;
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequest;
import com.okta.idx.sdk.api.response.IDXResponse;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

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
     * @param client the {@link IDXClient} instance
     * @param request the request to Okta Identity Engine
     * @return IDXResponse the response from Okta Identity Engine
     *
     * @throws IllegalArgumentException MUST throw this exception when provided data does not contain all required data for the proceed call.
     * @throws IllegalStateException MUST throw this exception when proceed is called with an invalid/unsupported request type.
     * @throws ProcessingException when the proceed operation encountered an execution/processing error.
     */
    public IDXResponse proceed(IDXClient client, Object request) throws IllegalStateException, IllegalArgumentException, ProcessingException {
        Assert.notNull(request, "request cannot be null");

        if (request instanceof IdentifyRequest) return client.identify((IdentifyRequest) request, href);
        else if (request instanceof ChallengeRequest) return client.challenge((ChallengeRequest) request, href);
        else if (request instanceof AnswerChallengeRequest)
            return client.answerChallenge((AnswerChallengeRequest) request, href);
        else if (request instanceof EnrollRequest) return client.enroll((EnrollRequest) request, href);
        else if (request instanceof EnrollUserProfileUpdateRequest) return client.enrollUpdateUserProfile((EnrollUserProfileUpdateRequest) request, href);
        else if (request instanceof SkipAuthenticatorEnrollmentRequest) return client.skip((SkipAuthenticatorEnrollmentRequest) request, href);
        else if (request instanceof RecoverRequest) return client.recover((RecoverRequest) request, href);
        else
            throw new IllegalStateException("Cannot invoke proceed with the supplied request type " + request.getClass().getSimpleName());
    }

    /**
     * Get all form values.
     *
     * @return array an array of FormValue
     */
    public FormValue[] form() {
        return Arrays.copyOf(value, value.length);
    }

    public String getName() {
        return name;
    }

    /**
     * Get a key-value pair map of Authenticator options available for the current remediation option.
     *
     * where
     * key - authenticator type (e.g. password, security_question, email)
     * value - authenticator id (e.g. aut2ihzk2n15tsQnQ1d6)
     *
     * @return map of Authenticator type and id
     */
    public Map<String, String> getAuthenticatorOptions() {

        Map<String, String> authenticatorOptionsMap = new HashMap<>();

        FormValue[] formValues = this.form();

        Optional<FormValue> formValueOptional = Arrays.stream(formValues)
            .filter(x -> "authenticator".equals(x.getName()))
            .findFirst();

        if (formValueOptional.isPresent()) {
            Options[] options = formValueOptional.get().options();

            for (Options option : options) {
                String key = null, val = null;
                FormValue[] optionFormValues = ((OptionsForm) option.getValue()).getForm().getValue();
                for (FormValue formValue : optionFormValues) {
                    if (formValue.getName().equals("methodType")) {
                        key = String.valueOf(formValue.getValue());
                        StringBuilder nestedKeys = new StringBuilder();
                        if (key.equals("null")) {
                            // parse value from children
                            for (Options children : formValue.options()) {
                                nestedKeys.append(children.getValue());
                                nestedKeys.append(",");
                            }
                            nestedKeys = nestedKeys.deleteCharAt(nestedKeys.length() - 1);
                            key = nestedKeys.toString();
                        }
                    }
                    if (formValue.getName().equals("id")) {
                        val = String.valueOf(formValue.getValue());
                    }
                    if (formValue.getName().equals("enrollmentId")) {
                        authenticatorOptionsMap.put("enrollmentId", String.valueOf(formValue.getValue()));
                    }
                }
                if (key != null) {
                    authenticatorOptionsMap.put(key, val);
                }
            }
        }
        return authenticatorOptionsMap;
    }
}
