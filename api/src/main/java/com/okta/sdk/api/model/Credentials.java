package com.okta.sdk.api.model;

import com.fasterxml.jackson.annotation.JsonAutoDetect;

@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY)
public class Credentials {

    public String passcode;

    public String answer;

    public Credentials(String passcode, String answer) {
        this.passcode = passcode;
        this.answer = answer;
    }
}
