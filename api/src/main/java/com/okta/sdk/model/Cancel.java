package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Cancel {

    /**
     * Ion spec rel member based around the (form structure)[https://ionspec.org/#form-structure] rules
     */
    private String[] rel;

    /**
     * Identifier for the remediation option
     */
    private String name;

    /**
     * Href for the remediation option
     */
    private String href;

    /**
     * HTTP Method to use for this remediation option.
     */
    private String method;

    private FormValue[] value;

    /**
     * Accepts Header for this remediation option.
     */
    private String accepts;

    public FormValue[] getValue() {
        return value;
    }
}
