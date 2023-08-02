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
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.okta.idx.sdk.api.deserializers.OptionsValueDeserializer;

import java.io.Serializable;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Options implements Serializable {

    private static final long serialVersionUID = -336868731800413422L;
    private String label;

    @JsonDeserialize(using = OptionsValueDeserializer.class)
    private Object value;

    private String relatesTo;

    public String getLabel() {
        return label;
    }

    public Object getValue() {
        return value;
    }

    public String getRelatesTo() {
        return relatesTo;
    }
}
