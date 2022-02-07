/*
 * Copyright (c) 2022-Present, Okta, Inc.
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
package com.okta.spring.example.helpers;

import com.okta.idx.sdk.api.model.AuthenticationStatus;

import java.util.List;

public class PollResults {

    /**
     * Contains errors after poll request.
     */
    private List<String> errors;

    /**
     * Contains AuthenticationStatus after poll request.
     */
    private AuthenticationStatus status;

    /**
     * Return errors after poll request.
     *
     * @return List of errors
     */
    public List<String> getErrors() {
        return errors;
    }

    /**
     * Set errors after poll request.
     *
     * @param listErrors list of errors
     */
    public void setErrors(List<String> listErrors) {
        this.errors = listErrors;
    }

    /**
     * Get AuthenticationStatus after poll request.
     *
     * @return AuthenticationStatus value
     */
    public AuthenticationStatus getStatus() {
        return status;
    }

    /**
     * Set AuthenticationStatus after poll request.
     *
     * @param authenticationStatus is AuthenticationStatus value after poll request
     */
    public void setStatus(AuthenticationStatus authenticationStatus) {
        this.status = authenticationStatus;
    }
}
