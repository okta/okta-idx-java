package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class RemediationOption {

    /**
     * Ion spec rel member based around the (form structure)[https://ionspec.org/#form-structure] rules
     */
    private String[] rel;

    /**
     * Identifier for the remediation option
     */
    private String name;

    /**
     * HTTP Method to use for this remediation option.
     */
    private String method;

    /**
     * Href for the remediation option
     */
    private String href;

    private FormValue[] value;

    /**
     * Accepts Header for this remediation option.
     */
    private String accepts;

    /**
     * Allow you to continue the remediation with this option.
     *
     * @param mixed The data returned from the enduser
     *
     * @return OktaIdentityEngineResponse
     *
     * @throws InvalidArgumentException MUST throw this exception when provided data does not contain all required data for the proceed call.
     */
    //public OktaIdentityEngineResponse proceed($dataFromUi); //TODO: check how data from UI is passed here

    /**
     * Call this function after all remediation options have been completed. This
     * method calls and handles the success of a login.
     *
     * Spec defines this method name as `finalize()` which we cannot use because its a reserved method name.
     * Therefore, named it `finish()`. //TODO: discuss this with team
     *
     * @return String ??? TODO: discuss this with team
     */
    public String finish() {
        //TODO
        return null;
    }

    /**
     * Get all form values. This is generated from `$this->value`.
     * Each item in `$this->value` MUST be mapped to a `FormValue` object
     *
     * @return array an array of FormValue
     */
    public FormValue[] form() {
        return value;
    }

}
