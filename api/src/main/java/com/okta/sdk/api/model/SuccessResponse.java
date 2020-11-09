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
package com.okta.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.okta.commons.lang.Assert;

import java.util.Arrays;
import java.util.Optional;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class SuccessResponse {

    /**
     * Ion spec rel member based around the (form structure)[https://ionspec.org/#form-structure] rules
     */
    private String[] rel;

    /**
     * Identifier
     */
    private String name;

    /**
     * HTTP Method
     */
    private String method;

    /**
     * Href for token endpoint
     */
    private String href;

    /**
     * Array of form values
     */
    private FormValue[] value;

    /**
     * Accepts Header
     */
    private String accepts;

    /**
     *
     * @return {@link Token} array of token objects
     */
    public Token[] exchangeCode() {

        Optional<FormValue> grantTypeForm = Arrays.stream(this.value)
            .filter(x -> "grant_type".equals(x.getName()))
            .findAny();
        Assert.isTrue(grantTypeForm.isPresent());
        String interactionCodeLookupKey = String.valueOf(grantTypeForm.get().getValue());

        Optional<FormValue> interactionCodeForm = Arrays.stream(this.value)
            .filter(x -> interactionCodeLookupKey.equals(x.getName()))
            .findAny();
        Assert.isTrue(interactionCodeForm.isPresent());
        String interactionCode = String.valueOf(interactionCodeForm.get().getValue());
        Assert.notNull(interactionCode, "interaction_code cannot be null");

        Optional<FormValue> clientIdForm = Arrays.stream(this.value)
            .filter(x -> "client_id".equals(x.getName()))
            .findAny();
        Assert.isTrue(clientIdForm.isPresent());
        String clientId = String.valueOf(clientIdForm.get().getValue());
        Assert.notNull(clientId, "client_id cannot be null");

        return null;
    }
}
