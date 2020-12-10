/*
 * Copyright 2020-Present Okta, Inc.
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

import java.util.Arrays;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Cancel {

    /**
     * Ion spec rel member based around the (form structure)[https://ionspec.org/#form-structure] rules
     */
    private String[] rel;

    /**
     * Identifier for the remediation option
     */
    private String name;

    /**
     * Href for the remediation option
     */
    private String href;

    /**
     * HTTP Method to use for this remediation option.
     */
    private String method;

    private FormValue[] value;

    /**
     * Accepts Header for this remediation option.
     */
    private String accepts;

    public String[] getRel() {
        return Arrays.copyOf(this.rel, this.rel.length);
    }

    public String getName() {
        return name;
    }

    public String getHref() {
        return href;
    }

    public String getMethod() {
        return method;
    }

    public FormValue[] getValue() {
        return Arrays.copyOf(this.value, this.value.length);
    }

    public String getAccepts() {
        return accepts;
    }
}
