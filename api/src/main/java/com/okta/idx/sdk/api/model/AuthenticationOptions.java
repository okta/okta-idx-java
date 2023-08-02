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
package com.okta.idx.sdk.api.model;

import java.io.Serializable;
import java.util.Arrays;

public class AuthenticationOptions implements Serializable {

    private static final long serialVersionUID = -3884153710554509205L;
    private String username;

    private char[] password;

    public AuthenticationOptions(String username) {
        this.username = username;
    }

    public AuthenticationOptions(String username, char[] password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public char[] getPassword() {
        return password != null ? Arrays.copyOf(password, password.length) : null;
    }

    public void setPassword(char[] password) {
        this.password = password;
    }
}
