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
public class FormValue {

    /**
     * The name of the form item that can be used in a UI.
     * This relates to the name that is used for the body of the request for the RemediationStep.
     */
    public String name;

    /**
     * Indicates whether the item is a required field
     */
    public boolean required;

    /**
     * A user friendly name that could be used for a UI
     */
    public String label;

    /**
     * Describes the type of value that is expected
     */
    public String type;

    /**
     * Is the value a secret value
     */
    public boolean secret;

    /**
     * Default value for the current form value
     */
    public Object value;

    private OptionsFormVal form;

    public Options[] options;

    /**
     * Should this form value be visible in a UI
     */
    public boolean visible;

    /**
     * Should this form value be mutable in a UI. MAY relate to the form fields disabled property
     */
    public boolean mutable;

    public String relatesTo() {
        return Arrays.stream(options).findFirst().get().getRelatesTo();
    }

    /**
     * return an array of FormValue objects
     *
     * @return {@link OptionsFormVal} array of FormValue
     */
    public OptionsFormVal form() {
        return this.form;
    }

    /**
     * return a list of options that is described as an array of formValue
     *
     * @return {@link Options} array
     */
    public Options[] options() {
        return Arrays.copyOf(this.options, this.options.length);
    }

    public String getName() {
        return name;
    }

    public boolean isRequired() {
        return required;
    }

    public Object getValue() {
        return value;
    }

    public OptionsFormVal getForm() {
        return form;
    }
}
