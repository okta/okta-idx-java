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
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.request.RecoverRequest;
import com.okta.idx.sdk.api.response.IDXResponse;

import java.io.Serializable;
import java.util.Arrays;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Recover implements Serializable {

    private static final long serialVersionUID = -4132909683378754087L;
    private String[] rel;

    private String name;

    private String href;

    private String method;

    private String produces;

    private String accepts;

    private FormValue[] value;

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

    public String getProduces() {
        return produces;
    }

    public String getAccepts() {
        return accepts;
    }

    public FormValue[] getValue() {
        return Arrays.copyOf(this.value, this.value.length);
    }

    public IDXResponse proceed(IDXClient client, RecoverRequest request) throws IllegalStateException, IllegalArgumentException, ProcessingException {
        return client.recover(request, getHref());
    }

}
