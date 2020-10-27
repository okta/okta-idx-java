package com.okta.sdk.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Options {

    private String label;

    private OptionsForm value;

    public String getLabel() {
        return label;
    }

    public OptionsForm getValue() {
        return value;
    }
}
