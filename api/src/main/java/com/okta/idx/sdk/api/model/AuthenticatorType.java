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

import java.util.HashMap;
import java.util.Map;

public enum AuthenticatorType {

    EMAIL("email"),

    PASSWORD("password"),

    SMS("sms"),

    VOICE("voice");

    private String value;

    AuthenticatorType(String value) {
        this.value = value;
    }

    public String getValue() { return this.value; }

    public static AuthenticatorType get(String authenticatorType) {
        return reverseLookupMap.get(authenticatorType);
    }

    @Override
    public String toString() {
        return String.valueOf(value);
    }

    static Map<String, AuthenticatorType> reverseLookupMap = new HashMap<>();

    static {
        AuthenticatorType[] values = AuthenticatorType.values();

        for (AuthenticatorType val : values) {
            reverseLookupMap.put(val.getValue(), val);
        }
    }
}
