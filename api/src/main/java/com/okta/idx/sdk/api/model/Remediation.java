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
public class Remediation implements Serializable {

    private static final long serialVersionUID = -812381060441737350L;
    /**
     * The type of the `value` value
     */
    private String type;

    private RemediationOption[] value;

    /**
     * The list of remediation options available to continue the flow based on `remediation.value`
     *
     * @return array array of RemediationOptions objects
     */
    public RemediationOption[] remediationOptions() {
        return Arrays.copyOf(value, value.length);
    }

    public String getType() {
        return type;
    }

    public RemediationOption[] getValue() {
        return Arrays.copyOf(value, value.length);
    }
}
