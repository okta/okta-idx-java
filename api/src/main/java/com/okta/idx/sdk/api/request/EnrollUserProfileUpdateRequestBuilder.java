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
import com.okta.idx.sdk.api.model.UserProfile;

public class EnrollUserProfileUpdateRequestBuilder {

    private String stateHandle;
    private UserProfile userProfile;

    private Credentials credentials;
    public static EnrollUserProfileUpdateRequestBuilder builder() {
        return new EnrollUserProfileUpdateRequestBuilder();
    }

    public EnrollUserProfileUpdateRequestBuilder withStateHandle(String stateHandle) {
        this.stateHandle = stateHandle;
        return this;
    }

    public EnrollUserProfileUpdateRequestBuilder withUserProfile(UserProfile userProfile) {
        this.userProfile = userProfile;
        return this;
    }

    public EnrollUserProfileUpdateRequestBuilder withCredentials(Credentials credentials) {
        this.credentials = credentials;
        return this;
    }
    public EnrollUserProfileUpdateRequest build() {
        return new EnrollUserProfileUpdateRequest(stateHandle, userProfile, credentials);
    }
}
