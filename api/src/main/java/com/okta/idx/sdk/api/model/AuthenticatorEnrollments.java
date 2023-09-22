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
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Stream;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class AuthenticatorEnrollments implements Iterable<AuthenticatorEnrollment>, Serializable {

    private static final long serialVersionUID = 1299561010501396979L;
    private String type;

    private List<AuthenticatorEnrollment> value;

    public String getType() {
        return type;
    }

    public List<AuthenticatorEnrollment> getValue() {
        return this.value;
    }

    public List<AuthenticatorEnrollment> getValues() {
        return value != null ? value : Collections.emptyList();
    }

    public List<AuthenticatorEnrollment> authenticatorEnrollments() { return getValues(); }

    public Stream<AuthenticatorEnrollment> stream() {
        return value != null ? getValue().stream() : Stream.empty();
    }

    @Override
    public Iterator<AuthenticatorEnrollment> iterator() {
        return stream().iterator();
    }
}
