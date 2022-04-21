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
package com.okta.idx.sdk.api.model;

import com.okta.commons.lang.Assert;

import java.util.HashMap;
import java.util.Map;

public class DeviceContext {

    private static final String USER_AGENT = "User-Agent";
    private static final String X_OKTA_USER_AGENT_EXTENDED = "X-Okta-User-Agent-Extended";
    private static final String X_DEVICE_TOKEN = "X-Device-Token";
    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    /**
     * store key value pairs of header name -> header value
     */
    private final Map<String, String> headers = new HashMap<>();

    public DeviceContext addUserAgentHeader(String value) {
        Assert.hasText(value, USER_AGENT + " cannot be empty");
        headers.put(USER_AGENT, value);
        return this;
    }

    public DeviceContext addXOktaUserAgentExtendedHeader(String value) {
        Assert.hasText(value, X_OKTA_USER_AGENT_EXTENDED + " cannot be empty");
        headers.put(X_OKTA_USER_AGENT_EXTENDED, value);
        return this;
    }

    public DeviceContext addXDeviceTokenHeader(String value) {
        Assert.hasText(value, X_DEVICE_TOKEN + " cannot be empty");
        headers.put(X_DEVICE_TOKEN, value);
        return this;
    }

    public DeviceContext addXForwardedForHeader(String value) {
        Assert.hasText(value, X_FORWARDED_FOR + " cannot be empty");
        headers.put(X_FORWARDED_FOR, value);
        return this;
    }

    public Map<String, String> getAllHeaders() {
        return headers;
    }
}
