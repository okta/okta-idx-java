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
import com.okta.sdk.api.client.IDXClient;
import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.response.TokenResponse;

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

    public String[] getRel() {
        return Arrays.copyOf(this.rel, this.rel.length);
    }

    public String getName() {
        return name;
    }

    public String getMethod() {
        return method;
    }

    public String getHref() {
        return href;
    }

    public FormValue[] getValue() {
        return Arrays.copyOf(this.value, this.value.length);
    }

    public String getAccepts() {
        return accepts;
    }

    public FormValue[] form() {
        return getValue();
    }

    /**
     * Parse grant_type from success response
     * @return grant_type
     */
    private String parseGrantType() {
        Optional<FormValue> grantTypeForm = Arrays.stream(this.value)
            .filter(x -> "grant_type".equals(x.getName()))
            .findAny();
        Assert.isTrue(grantTypeForm.isPresent());
        return String.valueOf(grantTypeForm.get().getValue());
    }

    /**
     * Parse interaction_code from success response
     * @return interaction_code
     */
    private String parseInteractionCode() {
        String interactionCodeLookupKey = this.parseGrantType();
        Optional<FormValue> interactionCodeForm = Arrays.stream(this.value)
            .filter(x -> interactionCodeLookupKey.equals(x.getName()))
            .findAny();
        Assert.isTrue(interactionCodeForm.isPresent());
        String interactionCode = String.valueOf(interactionCodeForm.get().getValue());
        return interactionCode;
    }

    /**
     * Parse client_id from success response
     * @return client_id
     */
    private String parseClientId() {
        Optional<FormValue> clientIdForm = Arrays.stream(this.value)
            .filter(x -> "client_id".equals(x.getName()))
            .findAny();
        Assert.isTrue(clientIdForm.isPresent());
        return String.valueOf(clientIdForm.get().getValue());
    }

    /**
     * Exchange interaction code for token
     *
     * @param client the idx client instance
     * @return TokenResponse
     */
    public TokenResponse exchangeCode(IDXClient client) throws ProcessingException {
        String grantType = this.parseGrantType();
        Assert.hasText(grantType, "grant_type cannot be empty");

        String interactionCode = this.parseInteractionCode();
        Assert.hasText(interactionCode, "interaction_code cannot be empty");

        String clientId = this.parseClientId();
        Assert.hasText(clientId, "client_id cannot be null");

        String tokenUrl = this.getHref();
        Assert.hasText(tokenUrl, "token url (href) cannot be empty");

        TokenResponse tokenResponse = client.token(tokenUrl, grantType, interactionCode);
        return tokenResponse;
    }
}
