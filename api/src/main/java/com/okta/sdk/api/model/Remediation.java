package com.okta.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Remediation {

    /**
     * The type of the `value` value
     */
    private String type;

    private RemediationOption[] value;

    /**
     * The list of remediation options available to continue the flow based on `remediation.value`
     *
     * @return array array of RemediationOptions objects
     */
    public RemediationOption[] remediationOptions() {
        return value;
    }
}
