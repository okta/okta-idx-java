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
package com.okta.idx.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

import java.io.Serializable;
import java.util.Arrays;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class AuthenticatorEnrollment implements Serializable {

    private static final long serialVersionUID = 2327419676285048622L;
    private Profile profile;

    private String type;

    private String id;

    private String key;

    private String displayName;

    private String credentialId;

    private MethodType[] methods;

    public Profile getProfile() {
        return profile;
    }

    public String getType() {
        return type;
    }

    public String getId() {
        return id;
    }

    public String getKey() { return key; }

    public String getDisplayName() {
        return displayName;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public MethodType[] getMethods() {
        return Arrays.copyOf(this.methods, this.methods.length);
    }
}
