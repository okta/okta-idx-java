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
package com.okta.idx.sdk.api.request;

import com.okta.idx.sdk.api.model.Credentials;

public class AnswerChallengeRequestBuilder {

    private String stateHandle;

    private Credentials credentials;

    private String phoneNumber;

    private String email;

    public static AnswerChallengeRequestBuilder builder() {
        return new AnswerChallengeRequestBuilder();
    }

    public AnswerChallengeRequestBuilder withStateHandle(String stateHandle) {
        this.stateHandle = stateHandle;
        return this;
    }

    public AnswerChallengeRequestBuilder withPhoneNumber(String phoneNumber) {
        this.phoneNumber = phoneNumber;
        return this;
    }

    public AnswerChallengeRequestBuilder withEmail(String email) {
        this.email = email;
        return this;
    }

    public AnswerChallengeRequestBuilder withCredentials(Credentials credentials) {
        this.credentials = credentials;
        return this;
    }

    public AnswerChallengeRequest build() {
        return new AnswerChallengeRequest(stateHandle, credentials, phoneNumber, email);
    }
}
