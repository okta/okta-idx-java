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
package com.okta.idx.sdk.api.model;

public enum AuthenticationStatus {

    SUCCESS("success"),

    SKIP_COMPLETE("skip_complete"),

    PASSWORD_EXPIRED("password_expired"),

    AWAITING_AUTHENTICATOR_SELECTION("awaiting_authenticator_selection"),

    AWAITING_AUTHENTICATOR_VERIFICATION("awaiting_authenticator_verification"),

    AWAITING_PASSWORD_RESET("awaiting_password_reset");

    private String value;

    AuthenticationStatus(String value) {
        this.value = value;
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }
}
