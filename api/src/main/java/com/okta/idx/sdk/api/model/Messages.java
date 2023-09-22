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
import com.okta.commons.lang.Strings;

import java.io.Serializable;
import java.util.List;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Messages implements Serializable {

    private static final long serialVersionUID = 8445952934174265463L;

    private String type;

    private List<MessageValue> value;

    public String getType() {
        return type;
    }

    public List<MessageValue> getValue() {
        return this.value;
    }

    public List<MessageValue> values() { return getValue(); }

    public boolean hasErrorValue() {
        return value.stream()
            .map(MessageValue::getValue)
            .anyMatch(val -> Strings.hasText(val) && "ERROR".equals(val));
    }
}
