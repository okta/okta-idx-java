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

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Holds few request HTTP headers.
 */
public class RequestContext {

    public static final String X_DEVICE_TOKEN = "X-Device-Token";
    public static final String X_OKTA_USER_AGENT_EXTENDED = "X-Okta-User-Agent-Extended";
    public static final String X_FORWARDED_FOR = "X-Forwarded-For";

    /**
     * store key value pairs of header name -> header value
     */
    private final Map<String, String> headers = new LinkedHashMap<>();

    public RequestContext addXOktaUserAgentExtendedHeader(String value) {
        Assert.hasText(value, X_OKTA_USER_AGENT_EXTENDED + " cannot be empty");
        headers.put(X_OKTA_USER_AGENT_EXTENDED, value);
        return this;
    }

    public RequestContext addXDeviceTokenHeader(String value) {
        Assert.hasText(value, X_DEVICE_TOKEN + " cannot be empty");
        headers.put(X_DEVICE_TOKEN, value);
        return this;
    }

    public RequestContext addXForwardedForHeader(String value) {
        Assert.hasText(value, X_FORWARDED_FOR + " cannot be empty");
        headers.put(X_FORWARDED_FOR, value);
        return this;
    }

    public Map<String, String> getAllHeaders() {
        return headers;
    }

    public String getXDeviceTokenHeaderValue() {
        return headers.get(X_DEVICE_TOKEN);
    }

    public String getXOktaUserAgentExtendedHeaderValue() {
        return headers.get(X_OKTA_USER_AGENT_EXTENDED);
    }

    public String getXForwardedForHeaderValue() {
        return headers.get(X_FORWARDED_FOR);
    }
}
