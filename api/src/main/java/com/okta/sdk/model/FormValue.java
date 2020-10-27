package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
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
     * Should this form value be mutable in a UI. MAY relate to the form fields `diabled` property
     */
    public boolean mutable;

    /**
     * Returns an object that is populated from the json path.
     * Example: `$.authenticatorEnrollments.value[0]` would ralate to the jsonPath `OktaIdentityEngine->raw()->authenticatorEnrollments->value[0]`
     *
     * @return stdObj|null
     */
    public Object relatesTo() {
        //TODO
        return null;
    }

    /**
     * In the case of a nested object, this will give you the items in the nest.
     * Example: if `$this->type == "object"`, form() will return an array of FormValue objects
     *
     * @return array array of FormValue
     */
    public Object form() {
        //TODO
        return value;
    }

    /**
     * A list of options that is described as an array of formValue.
     * Will be null if $this->type == "object" but `options` key does not exist
     *
     * @return array|null array of FormValue OR null
     */
    public Options[] options() {
        //TODO
        return options;
    }

    public String getName() {
        return name;
    }

    public Object getValue() {
        return value;
    }
}
