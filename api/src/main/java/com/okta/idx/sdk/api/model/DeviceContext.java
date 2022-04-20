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

import java.util.HashMap;
import java.util.Map;

public class DeviceContext {

    public final static String USER_AGENT = "User-Agent";
    public final static String X_OKTA_USER_AGENT_EXTENDED = "X-Okta-User-Agent-Extended";
    public final static String X_DEVICE_TOKEN = "X-Device-Token";
    public final static String X_FORWARDED_FOR = "X-Forwarded-For";

    /**
     * store key value pairs of header name -> header value
     */
    private final Map<String, String> headers = new HashMap<>();

    public DeviceContext addHeader(String name, String value) {
        headers.put(name, value);
        return this;
    }

    public String getHeader(String name) {
        return headers.get(name);
    }

    public Map<String, String> getAllHeaders() {
        return new HashMap<>(headers);
    }
}
