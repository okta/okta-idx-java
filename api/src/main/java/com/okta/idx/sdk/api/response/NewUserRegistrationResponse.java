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
package com.okta.idx.sdk.api.response;

import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;

import java.util.LinkedList;
import java.util.List;

public class NewUserRegistrationResponse {

    private IDXClientContext idxClientContext;

    private List<String> errors;

    private List<FormValue> formValues;

    public List<FormValue> getFormValues() {
        return formValues;
    }

    public void setFormValues(List<FormValue> formValues) {
        this.formValues = formValues;
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    public boolean addError(String error) {
        if (getErrors() == null) {
            this.errors = new LinkedList<>();
            return this.errors.add(error);
        }
        return getErrors().add(error);
    }

    public IDXClientContext getIdxClientContext() {
        return idxClientContext;
    }

    public void setIdxClientContext(IDXClientContext idxClientContext) {
        this.idxClientContext = idxClientContext;
    }
}
