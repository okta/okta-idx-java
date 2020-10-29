package com.okta.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Credentials {

    public String passcode;

    public Credentials(String passcode) {
        this.passcode = passcode;
    }
}
